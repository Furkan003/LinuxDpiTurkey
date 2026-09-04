//! # trdpi-transparent
//!
//! Sistem geneli koruma. Linux'ta nftables ile tüm giden TCP trafiğini yerel
//! bir dinleyiciye yönlendirir ve orada [`trdpi_proxy`] parçalama motorundan
//! geçirir.
//!
//! Farkı: uygulamalarda hiçbir ayar gerekmez. Discord, Sober ve diğer masaüstü
//! uygulamaları proxy ayarı bilmeden korunur.
//!
//! ## Yetki
//!
//! Yalnızca nftables kuralını kurmak yetki ister. Dinleyicinin kendisi normal
//! kullanıcı olarak çalışır.
//!
//! ## Kapsam
//!
//! TCP yakalanır ve korunur. UDP taşınmaz — ama profil isterse QUIC
//! (UDP 443) reddedilir, böylece uygulamalar korunan TCP yoluna düşer.
//! Yüksek portlardaki UDP'ye (oyunların gerçek zamanlı trafiği) hiç
//! dokunulmaz.

// Yalnızca iki syscall sarmalayıcısı unsafe kullanır; başka her yerde yasak.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod cleanup;
pub mod nft;
pub mod origdst;
pub mod retry;

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use trdpi_core::backend::{Backend, BackendError, EngineId, ProbeContext, ProbeResult, Snapshot};
use trdpi_core::profile::{FakeTrafficMode, FragmentationMode, Profile, QuicMode, TtlMode};
use trdpi_core::score::{HealthReport, ScoreInputs};
use trdpi_core::{Capabilities, Classification, Mechanism, SessionId};
use trdpi_proxy::{clienthello, server::write_fragments, split};

use nft::RedirectRules;

/// Şeffaf yönlendirme ayarları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentConfig {
    /// Yerel dinleyici portu.
    pub port: u16,
    /// Yakalanacak hedef portlar.
    pub capture_ports: Vec<u16>,
    /// Parçalar arası bekleme.
    pub split_delay: Duration,
    /// Hedefe bağlanma zaman aşımı.
    pub connect_timeout: Duration,
    /// Kesilen bağlantıyı yeniden deneme ayarları.
    pub retry: retry::RetryPolicy,
}

impl Default for TransparentConfig {
    fn default() -> Self {
        Self {
            port: 9443,
            capture_ports: vec![443],
            split_delay: Duration::from_millis(12),
            // TCP el sıkışması bir gidiş-dönüşte biter; kıtalar arası bir
            // hatta bile yarım saniye. Bunu aşan bekleme, yanıt gelmeyeceği
            // anlamına gelir. Cömert bir süre koymak yalnızca başarısız
            // bağlantıyı uzatır ve kullanıcı bunu yavaşlık olarak hisseder:
            // dört deneme, süre başına dört kat uzuyor.
            connect_timeout: Duration::from_secs(2),
            retry: retry::RetryPolicy::default(),
        }
    }
}

impl TransparentConfig {
    /// Özgün adres çalışmadığında kullanılan, daha aceleci ayar.
    ///
    /// Buraya gelindiğinde zaten bir tur beklenmiş oluyor. Alternatif adres
    /// çalışıyorsa hemen cevap verir; çalışmıyorsa ısrar etmenin anlamı yok —
    /// sıradakine geçmek daha hızlı.
    fn alternatif(&self) -> Self {
        Self {
            connect_timeout: Duration::from_secs(2),
            retry: retry::RetryPolicy {
                attempts: 1,
                first_byte_timeout: Duration::from_secs(2),
                ..self.retry
            },
            ..self.clone()
        }
    }
}

#[derive(Debug, Default)]
struct Counters {
    accepted: AtomicU64,
    failed: AtomicU64,
    fragmented: AtomicU64,
    retries: AtomicU64,
    established: AtomicU64,
    alternates: AtomicU64,
}

/// Motorun o ana kadarki sayaçları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Motora ulaşan bağlantı sayısı. Sıfırsa yönlendirme çalışmıyor.
    pub accepted: u64,
    /// Hedefe iletilemeyen bağlantı sayısı.
    pub failed: u64,
    /// İlk yazması parçalanarak gönderilen bağlantı sayısı.
    pub fragmented: u64,
    /// Kesilip yeniden denenen bağlantı sayısı.
    pub retries: u64,
    /// Sonunda kurulabilen bağlantı sayısı.
    pub established: u64,
    /// Özgün adres tümüyle çalışmadığı için başka bir adresten kurulan
    /// bağlantı sayısı.
    pub alternates: u64,
}

#[derive(Debug)]
struct Running {
    listener_addr: SocketAddr,
    /// Kuralların hâlâ yerinde olduğunu doğrulamak için tutulur.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    rules: RedirectRules,
    shutdown: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

/// Sistem geneli koruma motoru.
#[derive(Debug, Default)]
pub struct TransparentEngine {
    config: TransparentConfig,
    counters: Arc<Counters>,
    running: Mutex<Option<Running>>,
}

impl TransparentEngine {
    /// Verilen ayarlarla motor oluşturur.
    pub fn new(config: TransparentConfig) -> Self {
        Self {
            config,
            counters: Arc::new(Counters::default()),
            running: Mutex::new(None),
        }
    }

    /// Bu motorun profildeki tekniklerin tamamını uygulayıp uygulayamayacağı.
    ///
    /// Kullanıcı alanında çalıştığı için sahte paket ve TTL teknikleri
    /// yapılamaz; bunları isteyen profil reddedilir.
    pub fn supports_profile(profile: &Profile) -> bool {
        profile.strategy.fake_traffic == FakeTrafficMode::Off
            && profile.strategy.ttl == TtlMode::Off
            // QUIC üzerinde desync paket düzeyinde iş; kullanıcı alanında
            // yapılamaz. Geçirmek ve kapatmak yapılabilir.
            && profile.protocols.quic != QuicMode::Desync
    }

    /// Sayaçların anlık görüntüsü.
    ///
    /// Yönlendirmenin gerçekten çalışıp çalışmadığını buradan anlarsın:
    /// `accepted` sıfırsa hiçbir trafik motora uğramamış demektir.
    pub fn stats(&self) -> StatsSnapshot {
        StatsSnapshot {
            accepted: self.counters.accepted.load(Ordering::Relaxed),
            failed: self.counters.failed.load(Ordering::Relaxed),
            fragmented: self.counters.fragmented.load(Ordering::Relaxed),
            retries: self.counters.retries.load(Ordering::Relaxed),
            established: self.counters.established.load(Ordering::Relaxed),
            alternates: self.counters.alternates.load(Ordering::Relaxed),
        }
    }

    /// Motoru çalıştıran kullanıcının kimliği.
    #[allow(unsafe_code)]
    fn engine_uid() -> u32 {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: getuid her zaman başarılıdır ve yan etkisi yoktur.
            unsafe { libc::getuid() }
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }
}

impl Backend for TransparentEngine {
    fn id(&self) -> EngineId {
        EngineId::Native
    }

    fn mechanism(&self) -> Mechanism {
        Mechanism::TransparentProxy
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            mechanisms: vec![Mechanism::TransparentProxy],
            privilege_escalation: true,
            ipv6: false,
            // QUIC taşınmaz ama kapatılabilir; profil öyle diyorsa
            // uygulamalar korunan TCP yoluna düşer.
            quic_handling: true,
            dns_control: false,
            system_label: None,
        }
    }

    fn probe(&self, _ctx: &ProbeContext) -> Result<ProbeResult, BackendError> {
        #[cfg(not(target_os = "linux"))]
        {
            Ok(ProbeResult::unusable(
                Mechanism::TransparentProxy,
                "şeffaf yönlendirme yalnızca Linux'ta",
            ))
        }

        #[cfg(target_os = "linux")]
        {
            // Sistemi değiştirmeden yalnızca nft'nin var olduğunu sor.
            match nft::run(&["list".into(), "tables".into()]) {
                Ok(_) => Ok(ProbeResult::usable(Mechanism::TransparentProxy)),
                Err(nft::NftError::NotFound) => Ok(ProbeResult::unusable(
                    Mechanism::TransparentProxy,
                    "nftables kurulu değil",
                )),
                Err(nft::NftError::Denied) => Ok(ProbeResult::unusable(
                    Mechanism::TransparentProxy,
                    "nftables için yetki yok",
                )),
                Err(e) => Ok(ProbeResult::unusable(
                    Mechanism::TransparentProxy,
                    e.to_string(),
                )),
            }
        }
    }

    fn prepare(&self, session: SessionId) -> Result<Snapshot, BackendError> {
        Ok(Snapshot::new(
            session,
            EngineId::Native,
            Mechanism::TransparentProxy,
        ))
    }

    fn apply(&self, profile: &Profile, snapshot: &mut Snapshot) -> Result<(), BackendError> {
        if !Self::supports_profile(profile) {
            return Err(BackendError::ApplyFailed(
                "şeffaf yönlendirme sahte paket veya TTL tekniği uygulayamaz".into(),
            ));
        }

        let mut slot = self
            .running
            .lock()
            .map_err(|_| BackendError::ApplyFailed("motor kilidi bozuldu".into()))?;
        if slot.is_some() {
            return Err(BackendError::Conflict("koruma zaten çalışıyor".into()));
        }

        // Önce dinleyici: kural kurulup da dinleyen olmazsa tüm trafik kesilir.
        let listener = TcpListener::bind(("127.0.0.1", self.config.port))
            .map_err(|e| BackendError::ApplyFailed(format!("dinleyici açılamadı: {e}")))?;
        let listener_addr = listener
            .local_addr()
            .map_err(|e| BackendError::ApplyFailed(e.to_string()))?;

        let mut rules =
            RedirectRules::new(&snapshot.session, listener_addr.port(), Self::engine_uid());
        rules.ports = self.config.capture_ports.clone();
        rules.quic_block = profile.protocols.quic == QuicMode::Block;

        install_rules(&rules)?;
        // Kural kurulduğu anda temizlik listesine girer; bir sonraki adım
        // başarısız olsa bile geri alınabilir olmalı.
        snapshot.record(rules.table.clone());

        let shutdown = Arc::new(AtomicBool::new(false));
        let worker = {
            let shutdown = Arc::clone(&shutdown);
            let counters = Arc::clone(&self.counters);
            let fragmentation = profile.strategy.fragmentation;
            let config = self.config.clone();
            thread::spawn(move || {
                for incoming in listener.incoming() {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(client) = incoming else { continue };

                    let counters = Arc::clone(&counters);
                    let config = config.clone();
                    counters.accepted.fetch_add(1, Ordering::Relaxed);

                    thread::spawn(move || {
                        if handle(client, listener_addr, fragmentation, &config, &counters).is_err()
                        {
                            counters.failed.fetch_add(1, Ordering::Relaxed);
                        }
                    });
                }
            })
        };

        *slot = Some(Running {
            listener_addr,
            rules,
            shutdown,
            worker: Some(worker),
        });
        Ok(())
    }

    fn verify(&self) -> Result<HealthReport, BackendError> {
        let slot = self
            .running
            .lock()
            .map_err(|_| BackendError::VerifyFailed)?;
        let running = slot.as_ref().ok_or(BackendError::VerifyFailed)?;
        // Kural doğrulaması yalnızca Linux'ta anlamlı.
        #[cfg(not(target_os = "linux"))]
        let _ = running;

        // Kuralların hâlâ yerinde olduğunu doğrula; başka bir araç silmiş olabilir.
        #[cfg(target_os = "linux")]
        if nft::run(&running.rules.verify_command()).is_err() {
            return Err(BackendError::ApplyFailed(
                "yönlendirme kuralları kaybolmuş".into(),
            ));
        }

        let accepted = self.counters.accepted.load(Ordering::Relaxed);
        let failed = self.counters.failed.load(Ordering::Relaxed);

        if accepted == 0 {
            // Henüz trafik geçmedi; sağlık hakkında bir şey söyleyemeyiz.
            return Ok(HealthReport::new(
                ScoreInputs::default(),
                Classification::Unknown,
            ));
        }

        let success = accepted.saturating_sub(failed) as f64 / accepted as f64;
        Ok(HealthReport::new(
            ScoreInputs {
                availability: success,
                handshake_success: success,
                http_success: success,
                latency_health: 1.0,
                reset_health: success,
                loss_health: 1.0,
                dns_integrity: 1.0,
                quic_success: 0.0,
            },
            if success > 0.5 {
                Classification::Healthy
            } else {
                Classification::Degraded
            },
        ))
    }

    fn stop(&self, snapshot: Snapshot) -> Result<(), BackendError> {
        self.rollback(snapshot)
    }

    fn rollback(&self, snapshot: Snapshot) -> Result<(), BackendError> {
        let mut slot = self
            .running
            .lock()
            .map_err(|_| BackendError::RollbackFailed("motor kilidi bozuldu".into()))?;

        // Kuralı önce kaldır: dinleyici kapanıp kural kalırsa tüm TCP trafiği
        // var olmayan bir porta yönlenir ve ağ tamamen kopar.
        let mut hata = None;
        for table in &snapshot.owned_objects {
            if let Err(e) = uninstall_table(table) {
                hata = Some(e);
            }
        }

        if let Some(mut running) = slot.take() {
            running.shutdown.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect_timeout(&running.listener_addr, Duration::from_millis(500));
            if let Some(w) = running.worker.take() {
                let _ = w.join();
            }
        }

        match hata {
            Some(e) => Err(BackendError::RollbackFailed(e)),
            None => Ok(()),
        }
    }
}

#[cfg(target_os = "linux")]
fn install_rules(rules: &RedirectRules) -> Result<(), BackendError> {
    for (i, cmd) in rules.install_commands().into_iter().enumerate() {
        if let Err(e) = nft::run(&cmd) {
            // Yarım kurulmuş kural bırakma.
            let _ = nft::run(&rules.uninstall_command());
            return Err(match e {
                nft::NftError::Denied => BackendError::PrivilegeDenied,
                nft::NftError::NotFound => BackendError::MissingCapability("nftables"),
                other => BackendError::ApplyFailed(format!("{i}. kural: {other}")),
            });
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_rules(_rules: &RedirectRules) -> Result<(), BackendError> {
    Err(BackendError::MissingCapability("nftables"))
}

#[cfg(target_os = "linux")]
fn uninstall_table(table: &str) -> Result<(), String> {
    let cmd: Vec<String> = ["delete", "table", "inet", table]
        .iter()
        .map(|s| s.to_string())
        .collect();
    match nft::run(&cmd) {
        Ok(_) => Ok(()),
        // Tablo zaten yoksa iş bitmiş demektir.
        Err(nft::NftError::Failed(m)) if m.contains("No such file") => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(not(target_os = "linux"))]
fn uninstall_table(_table: &str) -> Result<(), String> {
    Ok(())
}

/// İlk yanıtı, ayırt edilebilir biçimde bekler.
fn read_first_response(
    upstream: &mut TcpStream,
    timeout: Duration,
) -> io::Result<retry::FirstResponse> {
    upstream.set_read_timeout(Some(timeout))?;
    let mut buf = vec![0u8; 8 * 1024];
    match upstream.read(&mut buf) {
        Ok(0) => Ok(retry::FirstResponse::Closed),
        Ok(n) => {
            buf.truncate(n);
            Ok(retry::FirstResponse::Data(buf))
        }
        Err(e) => match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                Ok(retry::FirstResponse::Timeout)
            }
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
                Ok(retry::FirstResponse::Reset)
            }
            _ => match e.raw_os_error() {
                Some(104) | Some(10054) => Ok(retry::FirstResponse::Reset),
                Some(110) | Some(10060) => Ok(retry::FirstResponse::Timeout),
                _ => Err(e),
            },
        },
    }
}

/// Bağlantıyı kurar; kesilirse yeniden dener.
///
/// İstemciye henüz hiçbir bayt gitmediği için yeniden deneme görünmez:
/// istemci yalnızca başarılı olan denemenin sonucunu görür.
fn connect_with_retry(
    target: SocketAddr,
    first: &[u8],
    fragmentation: FragmentationMode,
    config: &TransparentConfig,
    counters: &Counters,
) -> io::Result<(TcpStream, Vec<u8>)> {
    let policy = config.retry;
    let mut son_hata = None;

    for attempt in 0..policy.attempts {
        let mut upstream = match TcpStream::connect_timeout(&target, config.connect_timeout) {
            Ok(s) => s,
            Err(e) => {
                son_hata = Some(e);
                if attempt + 1 < policy.attempts {
                    counters.retries.fetch_add(1, Ordering::Relaxed);
                    thread::sleep(retry::delay_for(attempt, &policy));
                    continue;
                }
                break;
            }
        };
        upstream.set_nodelay(true)?;

        let plan = split::plan(first, fragmentation);
        if plan.len() > 1 && attempt == 0 {
            counters.fragmented.fetch_add(1, Ordering::Relaxed);
        }
        if let Err(e) = write_fragments(&mut upstream, &plan, config.split_delay) {
            son_hata = Some(e);
            if attempt + 1 < policy.attempts {
                counters.retries.fetch_add(1, Ordering::Relaxed);
                thread::sleep(retry::delay_for(attempt, &policy));
                continue;
            }
            break;
        }

        let response = read_first_response(&mut upstream, policy.first_byte_timeout)?;
        if let retry::FirstResponse::Data(d) = response {
            // Yanıt geldi. Bundan sonra yeniden deneme yapılamaz.
            upstream.set_read_timeout(None)?;
            return Ok((upstream, d));
        }

        // İstemciye hâlâ hiçbir şey gitmedi, bu yüzden yeniden denemek güvenli.
        if !retry::should_retry(&response, attempt, &policy, false) {
            break;
        }
        counters.retries.fetch_add(1, Ordering::Relaxed);
        thread::sleep(retry::delay_for(attempt, &policy));
    }

    Err(son_hata.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::ConnectionReset,
            "bağlantı her denemede kesildi",
        )
    }))
}

/// Özgün adres çalışmadığında denenecek en fazla adres sayısı.
///
/// Sınır gerekli: engel gerçekten adres bazlıysa listedeki her adres sırayla
/// zaman aşımına uğrar ve kullanıcı bunu bekleme olarak hisseder. Üç adres,
/// CDN'lerin döndürdüğü listenin anlamlı bir bölümünü kapsıyor.
const EN_FAZLA_ALTERNATIF: usize = 3;

/// Bir adresin dış dünyada gerçekten hedef olabilecek bir adres olup
/// olmadığı.
///
/// Çözümleme sonucuna güvenilemez: zehirlenmiş bir yanıt yerel ağdaki bir
/// adresi gösterebilir ve o adrese bağlanmak, kullanıcının kendi ağındaki bir
/// makineye bağlanmak demek olurdu.
fn dis_adres(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation())
        }
        std::net::IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_multicast() || v6.is_unspecified()),
    }
}

/// Özgün adres hiç çalışmadığında denenecek başka adresler.
///
/// Aynı alan adı çoğu zaman birden fazla adreste duruyor. Engel adreslerin
/// yalnızca bir bölümüne konmuşsa kalanlardan biri çalışır — IPv4 kapalıyken
/// IPv6 açık olabilir, bu yüzden aileyi de kısıtlamıyoruz.
///
/// Alan adını istemcinin gönderdiği ClientHello'dan okuyoruz; başka türlü
/// elimizde yalnızca çalışmadığı belli olan adres olurdu.
fn alternatif_adresler(first: &[u8], target: SocketAddr) -> Vec<SocketAddr> {
    use std::net::ToSocketAddrs;

    let Some(sni) = clienthello::find_sni(first) else {
        return Vec::new();
    };

    let Ok(adresler) = (sni.host.as_str(), target.port()).to_socket_addrs() else {
        return Vec::new();
    };

    let mut secilen: Vec<SocketAddr> = Vec::new();
    for a in adresler {
        if a.ip() == target.ip() || !dis_adres(a.ip()) || secilen.contains(&a) {
            continue;
        }
        secilen.push(a);
        if secilen.len() == EN_FAZLA_ALTERNATIF {
            break;
        }
    }
    secilen
}

fn handle(
    client: TcpStream,
    listener_addr: SocketAddr,
    fragmentation: FragmentationMode,
    config: &TransparentConfig,
    counters: &Counters,
) -> io::Result<()> {
    client.set_nodelay(true)?;

    let target = origdst::original_destination(&client)?;
    if origdst::is_self(target, listener_addr) {
        // Yönlendirme kendimize dönmüş; döngüye girmeden kapat.
        return Ok(());
    }

    let mut client_read = client.try_clone()?;

    // İlk yazmayı saklıyoruz: yeniden denemede aynısını göndereceğiz.
    let mut first = vec![0u8; 16 * 1024];
    let n = client_read.read(&mut first)?;
    if n == 0 {
        return Ok(());
    }
    first.truncate(n);

    let (upstream, ilk_yanit) =
        match connect_with_retry(target, &first, fragmentation, config, counters) {
            Ok(v) => v,
            Err(e) => {
                // Adres tümüyle çalışmıyor. Aynı alan adının başka adresleri
                // varsa engel hepsine konmamış olabilir.
                //
                // Buraya yalnızca istemciye tek bayt bile gitmemişken
                // gelinir; bu yüzden başka bir adresten devam etmek görünmez.
                let mut sonuc = Err(e);
                let acele = config.alternatif();
                for alternatif in alternatif_adresler(&first, target) {
                    if let Ok(v) =
                        connect_with_retry(alternatif, &first, fragmentation, &acele, counters)
                    {
                        counters.alternates.fetch_add(1, Ordering::Relaxed);
                        sonuc = Ok(v);
                        break;
                    }
                }
                sonuc?
            }
        };
    counters.established.fetch_add(1, Ordering::Relaxed);

    let mut upstream_write = upstream.try_clone()?;
    let mut client_write = client.try_clone()?;

    // Beklerken okuduğumuz yanıtı istemciye iletiyoruz; bu andan sonra
    // yeniden deneme yapılamaz.
    client_write.write_all(&ilk_yanit)?;

    let down = thread::spawn(move || {
        let mut from = upstream;
        let mut to = client_write;
        let _ = io::copy(&mut from, &mut to);
        let _ = to.shutdown(Shutdown::Write);
    });

    let _ = io::copy(&mut client_read, &mut upstream_write);
    let _ = upstream_write.shutdown(Shutdown::Write);
    let _ = down.join();
    let _ = client.shutdown(Shutdown::Both);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trdpi_core::profile::FragmentationMode;

    #[test]
    fn yetenekler_dogru_bildiriliyor() {
        let e = TransparentEngine::default();

        assert!(e.mechanism().is_system_wide(), "sistem geneli olmalı");
        assert!(e.mechanism().requires_privilege());
        assert!(e.mechanism().mutates_system(), "snapshot zorunlu");
        assert!(e.capabilities().quic_handling, "QUIC kapatılabiliyor");
    }

    #[test]
    fn yapamayacagi_teknik_reddediliyor() {
        let mut p = Profile::baseline();
        p.strategy.fragmentation = FragmentationMode::SniAware;
        p.strategy.ttl = TtlMode::Auto;
        assert!(!TransparentEngine::supports_profile(&p));

        p.strategy.ttl = TtlMode::Off;
        p.strategy.fake_traffic = FakeTrafficMode::Fake;
        assert!(!TransparentEngine::supports_profile(&p));

        p.strategy.fake_traffic = FakeTrafficMode::Off;
        assert!(TransparentEngine::supports_profile(&p));

        // QUIC'i kapatmak yapılabilir; QUIC üzerinde desync yapılamaz.
        p.protocols.quic = QuicMode::Block;
        assert!(TransparentEngine::supports_profile(&p));
        p.protocols.quic = QuicMode::Desync;
        assert!(!TransparentEngine::supports_profile(&p));
    }

    /// Zehirlenmiş bir yanıt yerel ağdaki bir adresi gösterebilir; oraya
    /// bağlanmak kullanıcının kendi ağındaki bir makineye bağlanmak olurdu.
    #[test]
    fn yerel_adresler_alternatif_sayilmiyor() {
        for kotu in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
        ] {
            assert!(
                !dis_adres(kotu.parse().unwrap()),
                "dış adres sayıldı: {kotu}"
            );
        }

        for iyi in ["1.1.1.1", "162.159.128.233", "2606:4700::1111"] {
            assert!(dis_adres(iyi.parse().unwrap()), "reddedildi: {iyi}");
        }
    }

    /// SNI yoksa alan adını bilmiyoruz; uydurmak yerine hiç denemiyoruz.
    #[test]
    fn sni_yoksa_alternatif_aranmiyor() {
        let hedef: SocketAddr = "93.184.216.34:443".parse().unwrap();
        assert!(alternatif_adresler(b"bu bir ClientHello degil", hedef).is_empty());
        assert!(alternatif_adresler(&[], hedef).is_empty());
    }

    /// Test girdisi olarak asgari bir ClientHello kurar.
    fn client_hello(sni: &str) -> Vec<u8> {
        let mut sunucu_adi = vec![0x00];
        sunucu_adi.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sunucu_adi.extend_from_slice(sni.as_bytes());

        let mut liste = (sunucu_adi.len() as u16).to_be_bytes().to_vec();
        liste.extend_from_slice(&sunucu_adi);

        let mut ext = 0x0000u16.to_be_bytes().to_vec();
        ext.extend_from_slice(&(liste.len() as u16).to_be_bytes());
        ext.extend_from_slice(&liste);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0xAA; 32]); // random
        body.push(0); // session_id yok
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]); // cipher_suites
        body.extend_from_slice(&[0x01, 0x00]); // compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut kayit = vec![0x16, 0x03, 0x01];
        kayit.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        kayit.extend_from_slice(&hs);
        kayit
    }

    /// Çalışmadığı belli olan adresi tekrar denemek anlamsız.
    #[test]
    fn ozgun_adres_alternatif_listesine_girmiyor() {
        use std::net::ToSocketAddrs;

        let ilk = client_hello("localhost");
        assert_eq!(
            clienthello::find_sni(&ilk).map(|s| s.host),
            Some("localhost".to_string()),
            "test girdisi geçerli bir ClientHello değil"
        );

        // Çözümleme ortama bağlı; hangi adres dönerse dönsün özgün adres
        // listede olmamalı — ve yerel adresler hiç girmemeli.
        if let Some(hedef) = ("localhost", 443u16)
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
        {
            let alt = alternatif_adresler(&ilk, hedef);
            assert!(!alt.contains(&hedef));
            assert!(alt.is_empty(), "localhost dış adres sayıldı: {alt:?}");
        }
    }

    #[test]
    fn bos_snapshot_geri_alinabiliyor() {
        let e = TransparentEngine::default();
        let snap = e.prepare(SessionId::new()).unwrap();
        assert!(e.rollback(snap).is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn linux_disinda_kullanilamaz_bildiriliyor() {
        let e = TransparentEngine::default();
        let ctx = ProbeContext {
            capabilities: Capabilities::default(),
            session: SessionId::new(),
        };
        let r = e.probe(&ctx).unwrap();
        assert!(!r.usable);
        assert!(r.reason.is_some());
    }
}
