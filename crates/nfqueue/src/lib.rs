//! # trdpi-nfqueue
//!
//! Sahte paket + düşük TTL motoru. Türkiye'de gözlenen TLS reset engelini
//! aşmak için gereken teknik budur; parçalama yetmiyor.
//!
//! ## Akış
//!
//! ```text
//! nftables ──kuyruk──> motor
//!                        │
//!                        ├─ ClientHello mu?  hayır ──> olduğu gibi geçir
//!                        │
//!                        └─ evet ──> sahte kopya üret (TTL düşük, zararsız SNI)
//!                                    ham soketten gönder
//!                                    gerçek paketi geçir
//! ```
//!
//! ## Güvenlik
//!
//! Kuyruk kuralı `bypass` bayrağıyla kurulur: motor çökerse paketler
//! düşürülmez, olduğu gibi geçer. Koruma kalkar ama **internet kesilmez.**
//! Şeffaf yönlendirmede bu güvence yoktu, burada var.
//!
//! Gönderdiğimiz sahte paketler işaretlenir ve kuyruğa yeniden alınmaz.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod fake;
pub mod nft;
pub mod packet;
pub mod quic;
pub mod raw;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use trdpi_core::backend::{Backend, BackendError, EngineId, ProbeContext, ProbeResult, Snapshot};
use trdpi_core::profile::{FragmentationMode, Profile, QuicMode, TtlMode};
use trdpi_core::score::{HealthReport, ScoreInputs};
use trdpi_core::{Capabilities, Classification, Mechanism, SessionId};

use nft::QueueRules;

/// Motor ayarları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfqueueConfig {
    /// Kullanılacak kuyruk numarası.
    pub queue_num: u16,
    /// Yakalanacak hedef portlar.
    pub capture_ports: Vec<u16>,
    /// Sahte pakette kullanılacak zararsız alan adı.
    pub fake_host: Vec<u8>,
    /// QUIC için kuyruğa alınacak UDP kapıları.
    pub quic_ports: Vec<u16>,
    /// QUIC sahte paketlerinde denenecek bozma yöntemleri.
    ///
    /// Birden fazla yöntem, farklı denetimlerde de tutması için. Maliyeti
    /// bağlantı başına birkaç pakete kalıyor.
    pub quic_bozmalar: Vec<quic::Bozma>,
}

impl Default for NfqueueConfig {
    fn default() -> Self {
        Self {
            queue_num: 4200,
            capture_ports: vec![443],
            fake_host: fake::DEFAULT_FAKE_HOST.to_vec(),
            quic_ports: vec![443],
            quic_bozmalar: quic::default_bozmalar(),
        }
    }
}

#[derive(Debug, Default)]
struct Counters {
    seen: AtomicU64,
    faked: AtomicU64,
    quic_seen: AtomicU64,
    quic_faked: AtomicU64,
    build_errors: AtomicU64,
    send_errors: AtomicU64,
}

/// Motorun o ana kadarki sayaçları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Kuyruktan geçen paket sayısı.
    pub seen: u64,
    /// Sahte kopya gönderilen paket sayısı.
    pub faked: u64,
    /// Kuyruktan geçen QUIC Initial sayısı.
    pub quic_seen: u64,
    /// Sahte kopya gönderilen QUIC Initial sayısı.
    pub quic_faked: u64,
    /// Sahte paket kurulamayan durum sayısı.
    pub build_errors: u64,
    /// Sahte paket kurulup da gönderilemeyen durum sayısı.
    pub send_errors: u64,
}

impl StatsSnapshot {
    /// Toplam hata sayısı.
    pub fn errors(&self) -> u64 {
        self.build_errors + self.send_errors
    }
}

/// TCP sahte paketi sonradan açılırsa kullanılacak ömür.
const DEFAULT_TCP_TTL: u8 = 5;

/// Verilen kuralların TCP kapıları için kuyruk kuralı ekler.
#[cfg(target_os = "linux")]
fn add_tcp_rules(rules: &QueueRules) -> Result<(), BackendError> {
    for cmd in rules.tcp_commands() {
        nft::run(&cmd).map_err(|e| BackendError::ApplyFailed(e.to_string()))?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn add_tcp_rules(_rules: &QueueRules) -> Result<(), BackendError> {
    Err(BackendError::MissingCapability("nftables"))
}

/// Kuyruk işçisine geçirilen ayarlar.
struct WorkerConfig {
    queue_num: u16,
    /// TCP sahte paketinin ömrü; `None` ise TCP tarafında iş yapılmaz.
    ttl: Option<u8>,
    fake_host: Vec<u8>,
    /// QUIC sahte paketlerinde denenecek yöntemler; boşsa QUIC'e dokunulmaz.
    quic_bozmalar: Vec<quic::Bozma>,
}

#[derive(Debug)]
struct Running {
    /// Kuralların yerinde olduğunu doğrulamak için tutulur.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    rules: QueueRules,
    shutdown: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

/// Sahte paket + TTL motoru.
#[derive(Debug, Default)]
pub struct NfqueueEngine {
    config: NfqueueConfig,
    counters: Arc<Counters>,
    running: Mutex<Option<Running>>,
}

impl NfqueueEngine {
    /// Verilen ayarlarla motor oluşturur.
    pub fn new(config: NfqueueConfig) -> Self {
        Self {
            config,
            counters: Arc::new(Counters::default()),
            running: Mutex::new(None),
        }
    }

    /// TCP sahte paketini çalışma anında devreye alır.
    ///
    /// Kuyruk kuralı baştan kurulmuyor: her TCP paketini kullanıcı alanına
    /// taşımak boşuna gecikme demek. Bu teknik gerektiğinde — yani başka
    /// yöntemler yetmediğinde — kural o an ekleniyor.
    ///
    /// İşçi zaten TCP yolunu biliyor; yalnızca kuyruğa paket gelmiyordu.
    pub fn tcp_yakalamayi_ac(&self) -> Result<(), BackendError> {
        let slot = self
            .running
            .lock()
            .map_err(|_| BackendError::ApplyFailed("motor kilidi bozuldu".into()))?;
        let Some(running) = slot.as_ref() else {
            return Err(BackendError::ApplyFailed("motor çalışmıyor".into()));
        };
        if running.rules.ports.is_empty() {
            return Err(BackendError::ApplyFailed("yakalanacak kapı yok".into()));
        }
        add_tcp_rules(&running.rules)
    }

    /// Sayaçların anlık görüntüsü.
    pub fn stats(&self) -> StatsSnapshot {
        StatsSnapshot {
            seen: self.counters.seen.load(Ordering::Relaxed),
            faked: self.counters.faked.load(Ordering::Relaxed),
            quic_seen: self.counters.quic_seen.load(Ordering::Relaxed),
            quic_faked: self.counters.quic_faked.load(Ordering::Relaxed),
            build_errors: self.counters.build_errors.load(Ordering::Relaxed),
            send_errors: self.counters.send_errors.load(Ordering::Relaxed),
        }
    }

    /// Profilin istediği TTL değeri.
    ///
    /// Sahte paketin inceleme donanımını geçip sunucuya varmadan ölmesi
    /// gerekir; bu yüzden değer küçük olmalıdır.
    pub fn fake_ttl(profile: &Profile) -> Option<u8> {
        match profile.strategy.ttl {
            TtlMode::Off => None,
            TtlMode::Fixed { hops } => Some(hops),
            // Ölçüm yokken makul bir başlangıç; ileride yol uzunluğundan
            // türetilecek.
            TtlMode::Auto => Some(5),
        }
    }

    /// Bu motorun profili uygulayıp uygulayamayacağı.
    ///
    /// TCP tarafında TTL kapalıysa ve QUIC desync de istenmiyorsa yapacak bir
    /// şey yoktur — o durumda parçalama motorları daha uygundur.
    pub fn supports_profile(profile: &Profile) -> bool {
        Self::fake_ttl(profile).is_some() || Self::quic_desync(profile)
    }

    /// Profil QUIC üzerinde desync istiyor mu?
    pub fn quic_desync(profile: &Profile) -> bool {
        profile.protocols.quic == QuicMode::Desync
    }
}

impl Backend for NfqueueEngine {
    fn id(&self) -> EngineId {
        EngineId::Native
    }

    fn mechanism(&self) -> Mechanism {
        Mechanism::Nfqueue
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            mechanisms: vec![Mechanism::Nfqueue],
            privilege_escalation: true,
            ipv6: false,
            quic_handling: false,
            dns_control: false,
            system_label: None,
        }
    }

    fn probe(&self, _ctx: &ProbeContext) -> Result<ProbeResult, BackendError> {
        #[cfg(not(target_os = "linux"))]
        {
            Ok(ProbeResult::unusable(
                Mechanism::Nfqueue,
                "NFQUEUE yalnızca Linux'ta",
            ))
        }

        #[cfg(target_os = "linux")]
        {
            // Ham soket açabiliyor muyuz? Bu, yetkinin gerçek sınavıdır.
            match raw::RawSender::new() {
                Ok(_) => match nft::run(&["list".into(), "tables".into()]) {
                    Ok(_) => Ok(ProbeResult::usable(Mechanism::Nfqueue)),
                    Err(nft::NftError::NotFound) => Ok(ProbeResult::unusable(
                        Mechanism::Nfqueue,
                        "nftables kurulu değil",
                    )),
                    Err(e) => Ok(ProbeResult::unusable(Mechanism::Nfqueue, e.to_string())),
                },
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(
                    ProbeResult::unusable(Mechanism::Nfqueue, "ham paket yetkisi yok"),
                ),
                Err(e) => Ok(ProbeResult::unusable(Mechanism::Nfqueue, e.to_string())),
            }
        }
    }

    fn prepare(&self, session: SessionId) -> Result<Snapshot, BackendError> {
        Ok(Snapshot::new(session, EngineId::Native, Mechanism::Nfqueue))
    }

    fn apply(&self, profile: &Profile, snapshot: &mut Snapshot) -> Result<(), BackendError> {
        let ttl = Self::fake_ttl(profile);
        let quic = Self::quic_desync(profile);
        if ttl.is_none() && !quic {
            return Err(BackendError::ApplyFailed(
                "bu motor TTL tekniği ya da QUIC desync olmadan bir işe yaramaz".into(),
            ));
        }

        let mut slot = self
            .running
            .lock()
            .map_err(|_| BackendError::ApplyFailed("motor kilidi bozuldu".into()))?;
        if slot.is_some() {
            return Err(BackendError::Conflict("motor zaten çalışıyor".into()));
        }

        let mut rules = QueueRules::new(&snapshot.session, self.config.queue_num);
        // Yalnızca gerçekten iş yapacağımız trafiği kuyruğa alıyoruz; boşuna
        // kuyruğa alınan her paket gecikme demek.
        // Kapılar saklanıyor ama kural baştan kurulmuyor; teknik
        // gerektiğinde açılıyor. Kuyruğa boşuna paket taşımıyoruz.
        rules.ports = self.config.capture_ports.clone();
        rules.tcp_active = false;
        rules.udp_ports = if quic {
            self.config.quic_ports.clone()
        } else {
            Vec::new()
        };

        // Kuyruğu önce açıyoruz: kural kurulup dinleyen olmazsa `bypass`
        // sayesinde trafik yine geçer, ama koruma da olmaz.
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker = start_worker(
            WorkerConfig {
                queue_num: self.config.queue_num,
                // İşçi TCP yolunu biliyor; kural eklenene kadar o yola paket
                // gelmiyor. Böylece teknik sonradan açılabiliyor.
                ttl: ttl.or(Some(DEFAULT_TCP_TTL)),
                fake_host: self.config.fake_host.clone(),
                quic_bozmalar: if quic {
                    self.config.quic_bozmalar.clone()
                } else {
                    Vec::new()
                },
            },
            Arc::clone(&self.counters),
            Arc::clone(&shutdown),
        )?;

        install_rules(&rules)?;
        snapshot.record(rules.table.clone());

        *slot = Some(Running {
            rules,
            shutdown,
            worker,
        });
        Ok(())
    }

    fn verify(&self) -> Result<HealthReport, BackendError> {
        let slot = self
            .running
            .lock()
            .map_err(|_| BackendError::VerifyFailed)?;
        let running = slot.as_ref().ok_or(BackendError::VerifyFailed)?;

        #[cfg(target_os = "linux")]
        if nft::run(&running.rules.verify_command()).is_err() {
            return Err(BackendError::ApplyFailed("kuyruk kuralı kaybolmuş".into()));
        }
        #[cfg(not(target_os = "linux"))]
        let _ = running;

        let seen = self.counters.seen.load(Ordering::Relaxed);
        let errors = self.stats().errors();

        if seen == 0 {
            // Hiç paket görmedik; sağlık hakkında bir şey söyleyemeyiz.
            return Ok(HealthReport::new(
                ScoreInputs::default(),
                Classification::Unknown,
            ));
        }

        let success = seen.saturating_sub(errors) as f64 / seen as f64;
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

        // Önce kural, sonra kuyruk. Ters sırada kuyruk kapanır ve kural
        // `bypass` sayesinde zararsız kalırdı, ama bu sıra daha temiz.
        let mut hata = None;
        for table in &snapshot.owned_objects {
            if let Err(e) = uninstall_table(table) {
                hata = Some(e);
            }
        }

        if let Some(mut running) = slot.take() {
            running.shutdown.store(true, Ordering::SeqCst);
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

/// Kuyruğu dinleyen işlemciyi başlatır.
#[cfg(target_os = "linux")]
fn start_worker(
    config: WorkerConfig,
    counters: Arc<Counters>,
    shutdown: Arc<AtomicBool>,
) -> Result<Option<std::thread::JoinHandle<()>>, BackendError> {
    use nfq::{Queue, Verdict};

    let WorkerConfig {
        queue_num,
        ttl,
        fake_host,
        quic_bozmalar,
    } = config;

    let sender = raw::RawSender::new().map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => BackendError::PrivilegeDenied,
        _ => BackendError::ApplyFailed(format!("ham soket açılamadı: {e}")),
    })?;

    let mut queue =
        Queue::open().map_err(|e| BackendError::ApplyFailed(format!("kuyruk açılamadı: {e}")))?;
    queue
        .bind(queue_num)
        .map_err(|e| BackendError::ApplyFailed(format!("kuyruğa bağlanılamadı: {e}")))?;
    // Kapanış bayrağını düzenli kontrol edebilmek için bloklamayan kip.
    queue.set_nonblocking(true);

    let handle = std::thread::spawn(move || {
        let mut tohum: u64 = 0x9E37_79B9_7F4A_7C15;
        while !shutdown.load(Ordering::SeqCst) {
            let mut msg = match queue.recv() {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                // Kuyruk okunamıyorsa paketi tutmaktansa döngüden çıkmak
                // daha güvenli: `bypass` devreye girer ve trafik akmaya devam eder.
                Err(_) => break,
            };

            counters.seen.fetch_add(1, Ordering::Relaxed);

            let payload = msg.get_payload();

            // QUIC: Initial paketinden hemen önce düşük ömürlü sahteler.
            if !quic_bozmalar.is_empty() {
                let initial = quic::udp_payload_offset(payload)
                    .and_then(|b| payload.get(b..))
                    .is_some_and(quic::is_initial);
                if initial {
                    counters.quic_seen.fetch_add(1, Ordering::Relaxed);
                    let mut gonderildi = false;
                    for b in &quic_bozmalar {
                        tohum = tohum.wrapping_add(0x9E37_79B9_7F4A_7C15);
                        match quic::build_fake(payload, *b, tohum) {
                            Some(f) => match sender.send(&f) {
                                Ok(()) => gonderildi = true,
                                Err(_) => {
                                    counters.send_errors.fetch_add(1, Ordering::Relaxed);
                                }
                            },
                            None => {
                                counters.build_errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    if gonderildi {
                        counters.quic_faked.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            if let (Some(ttl), true) = (ttl, fake::should_fake(payload)) {
                match fake::build_fake(payload, ttl, &fake_host) {
                    Ok(f) => match sender.send(&f) {
                        Ok(()) => {
                            counters.faked.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            counters.send_errors.fetch_add(1, Ordering::Relaxed);
                            if counters.send_errors.load(Ordering::Relaxed) <= 3 {
                                eprintln!("sahte paket gönderilemedi: {e}");
                            }
                        }
                    },
                    Err(e) => {
                        counters.build_errors.fetch_add(1, Ordering::Relaxed);
                        if counters.build_errors.load(Ordering::Relaxed) <= 3 {
                            eprintln!("sahte paket kurulamadı: {e}");
                        }
                    }
                }
            }

            // Gerçek paket her durumda geçer; sahte kopya onu engellemez.
            msg.set_verdict(Verdict::Accept);
            let _ = queue.verdict(msg);
        }
    });

    Ok(Some(handle))
}

#[cfg(not(target_os = "linux"))]
fn start_worker(
    _config: WorkerConfig,
    _counters: Arc<Counters>,
    _shutdown: Arc<AtomicBool>,
) -> Result<Option<std::thread::JoinHandle<()>>, BackendError> {
    Err(BackendError::MissingCapability("NFQUEUE"))
}

#[cfg(target_os = "linux")]
fn install_rules(rules: &QueueRules) -> Result<(), BackendError> {
    for (i, cmd) in rules.install_commands().into_iter().enumerate() {
        if let Err(e) = nft::run(&cmd) {
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
fn install_rules(_rules: &QueueRules) -> Result<(), BackendError> {
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
        Err(nft::NftError::Failed(m)) if m.contains("No such file") => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(not(target_os = "linux"))]
fn uninstall_table(_table: &str) -> Result<(), String> {
    Ok(())
}

/// Bu motorun anlamlı olduğu varsayılan profil.
///
/// GoodbyeDPI'ın Türkiye'de çalışan `--set-ttl 5` ayarına karşılık gelir.
pub fn default_profile() -> Profile {
    let mut p = Profile::baseline();
    p.name = "Sahte paket + TTL".into();
    p.description = "Düşük TTL'li sahte ClientHello gönderir.".into();
    p.supported_mechanisms = vec![Mechanism::Nfqueue];
    p.strategy.ttl = TtlMode::Fixed { hops: 5 };
    p.strategy.fragmentation = FragmentationMode::Off;
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varsayilan_profil_gecerli_ve_ttl_dusuk() {
        let p = default_profile();
        assert!(p.validate().is_ok());
        assert_eq!(NfqueueEngine::fake_ttl(&p), Some(5));
        assert!(NfqueueEngine::supports_profile(&p));
    }

    #[test]
    fn ttl_kapaliysa_motor_reddediyor() {
        let mut p = default_profile();
        p.strategy.ttl = TtlMode::Off;

        assert!(!NfqueueEngine::supports_profile(&p));

        let e = NfqueueEngine::default();
        let mut snap = e.prepare(SessionId::new()).unwrap();
        assert!(matches!(
            e.apply(&p, &mut snap).unwrap_err(),
            BackendError::ApplyFailed(_)
        ));
        assert!(snap.is_empty(), "başarısız apply kaynak kaydetmemeli");
    }

    #[test]
    fn auto_ttl_makul_bir_deger_veriyor() {
        let mut p = default_profile();
        p.strategy.ttl = TtlMode::Auto;

        let ttl = NfqueueEngine::fake_ttl(&p).unwrap();
        assert!(
            (2..=12).contains(&ttl),
            "TTL sunucuya varmayacak kadar küçük olmalı: {ttl}"
        );
    }

    #[test]
    fn yetenekler_dogru() {
        let e = NfqueueEngine::default();

        assert_eq!(e.mechanism(), Mechanism::Nfqueue);
        assert!(e.mechanism().is_system_wide());
        assert!(e.mechanism().requires_privilege());
        assert!(e.mechanism().mutates_system());
    }

    #[test]
    fn bos_snapshot_geri_alinabiliyor() {
        let e = NfqueueEngine::default();
        let snap = e.prepare(SessionId::new()).unwrap();
        assert!(e.rollback(snap).is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn linux_disinda_kullanilamaz() {
        let e = NfqueueEngine::default();
        let r = e
            .probe(&ProbeContext {
                capabilities: Capabilities::default(),
                session: SessionId::new(),
            })
            .unwrap();
        assert!(!r.usable);
    }
}
