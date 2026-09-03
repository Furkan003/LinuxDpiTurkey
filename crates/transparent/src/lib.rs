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
//! TCP yakalanır. UDP — dolayısıyla QUIC ve oyunların gerçek zamanlı trafiği —
//! bu mekanizmayla taşınmaz.

// Yalnızca iki syscall sarmalayıcısı unsafe kullanır; başka her yerde yasak.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod cleanup;
pub mod nft;
pub mod origdst;

use std::io::{self, Read};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use trdpi_core::backend::{Backend, BackendError, EngineId, ProbeContext, ProbeResult, Snapshot};
use trdpi_core::profile::{FakeTrafficMode, Profile, TtlMode};
use trdpi_core::score::{HealthReport, ScoreInputs};
use trdpi_core::{Capabilities, Classification, Mechanism, SessionId};
use trdpi_proxy::{server::write_fragments, split};

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
}

impl Default for TransparentConfig {
    fn default() -> Self {
        Self {
            port: 9443,
            capture_ports: vec![443],
            split_delay: Duration::from_millis(12),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Default)]
struct Counters {
    accepted: AtomicU64,
    failed: AtomicU64,
    fragmented: AtomicU64,
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
            // UDP yakalanmadığı için QUIC bu mekanizmadan geçmez.
            quic_handling: false,
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

fn handle(
    client: TcpStream,
    listener_addr: SocketAddr,
    fragmentation: trdpi_core::profile::FragmentationMode,
    config: &TransparentConfig,
    counters: &Counters,
) -> io::Result<()> {
    client.set_nodelay(true)?;

    let target = origdst::original_destination(&client)?;
    if origdst::is_self(target, listener_addr) {
        // Yönlendirme kendimize dönmüş; döngüye girmeden kapat.
        return Ok(());
    }

    let upstream = TcpStream::connect_timeout(&target, config.connect_timeout)?;
    upstream.set_nodelay(true)?;

    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;

    let mut first = vec![0u8; 16 * 1024];
    let n = client_read.read(&mut first)?;
    if n == 0 {
        return Ok(());
    }
    first.truncate(n);

    let plan = split::plan(&first, fragmentation);
    if plan.len() > 1 {
        counters.fragmented.fetch_add(1, Ordering::Relaxed);
    }
    write_fragments(&mut upstream_write, &plan, config.split_delay)?;

    let down = thread::spawn(move || {
        let mut from = upstream;
        let mut to = client;
        let _ = io::copy(&mut from, &mut to);
        let _ = to.shutdown(Shutdown::Write);
    });

    let _ = io::copy(&mut client_read, &mut upstream_write);
    let _ = upstream_write.shutdown(Shutdown::Write);
    let _ = down.join();

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
        assert!(!e.capabilities().quic_handling, "UDP yakalanmıyor");
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
