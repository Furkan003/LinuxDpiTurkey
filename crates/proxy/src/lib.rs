//! # trdpi-proxy
//!
//! Yerel SOCKS5 motoru. **Hiçbir ayrıcalık gerektirmez**, hiçbir firewall
//! kuralı yazmaz, hiçbir sistem ayarını değiştirmez — yalnızca geri döngü
//! adresinde bir dinleyici açar.
//!
//! ## Ne yapabilir, ne yapamaz
//!
//! Kullanıcı alanındaki bir proxy, TCP akışını **nerede böleceğine** karar
//! verebilir. Yapamayacağı şeyler:
//!
//! - sahte paket gönderme,
//! - TTL ile oynama,
//! - sıra dışı (disorder) gönderim.
//!
//! Bunların hepsi ham paket erişimi ister. [`ProxyEngine`] bu sınırı
//! [`ProxyEngine::supports_profile`] ile açıkça bildirir ve yapamayacağı bir
//! tekniği isteyen profili **sessizce yok saymaz** — reddeder. Sessizce yok
//! saymak, başarısızlığın yanlış sebebe atfedilmesine yol açardı.
//!
//! ## Kapsam
//!
//! Yalnızca proxy'ye yönlendirilen uygulamalar etkilenir. Sistem geneli koruma
//! için NFQUEUE gerekir; bu, [`trdpi_core::Mechanism::is_system_wide`]
//! üzerinden kullanıcıya dürüstçe bildirilir.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod clienthello;
pub mod server;
pub mod socks5;
pub mod split;

use std::sync::atomic::Ordering;
use std::sync::Mutex;

use trdpi_core::backend::{Backend, BackendError, EngineId, ProbeContext, ProbeResult, Snapshot};
use trdpi_core::profile::{FakeTrafficMode, Profile, TtlMode};
use trdpi_core::score::{HealthReport, ScoreInputs};
use trdpi_core::{Capabilities, Classification, Mechanism, SessionId};

pub use server::{ProxyConfig, ProxyHandle, Stats};

/// Yerel proxy motoru.
#[derive(Debug, Default)]
pub struct ProxyEngine {
    config: ProxyConfig,
    running: Mutex<Option<ProxyHandle>>,
}

impl ProxyEngine {
    /// Verilen ayarlarla motor oluşturur.
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            running: Mutex::new(None),
        }
    }

    /// Çalışıyorsa dinlenen adres.
    pub fn address(&self) -> Option<std::net::SocketAddr> {
        self.running.lock().ok()?.as_ref().map(ProxyHandle::address)
    }

    /// Bu motorun profildeki tekniklerin tamamını uygulayıp uygulayamayacağı.
    ///
    /// Yapamayacağı bir teknik istenmişse `false` döner; çağıran o profili
    /// aday listesinden çıkarmalıdır.
    pub fn supports_profile(profile: &Profile) -> bool {
        profile.strategy.fake_traffic == FakeTrafficMode::Off
            && profile.strategy.ttl == TtlMode::Off
    }
}

impl Backend for ProxyEngine {
    fn id(&self) -> EngineId {
        EngineId::Proxy
    }

    fn mechanism(&self) -> Mechanism {
        Mechanism::LocalProxy
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            mechanisms: vec![Mechanism::LocalProxy],
            // Geri döngüye bağlanmak yetki istemez.
            privilege_escalation: false,
            ipv6: true,
            // QUIC UDP'dir; SOCKS5 CONNECT ile taşınmaz.
            quic_handling: false,
            dns_control: false,
            system_label: None,
        }
    }

    fn probe(&self, _ctx: &ProbeContext) -> Result<ProbeResult, BackendError> {
        // Bu motor her sistemde çalışır; özel bir yetenek gerektirmez.
        Ok(ProbeResult::usable(Mechanism::LocalProxy))
    }

    fn prepare(&self, session: SessionId) -> Result<Snapshot, BackendError> {
        Ok(Snapshot::new(
            session,
            EngineId::Proxy,
            Mechanism::LocalProxy,
        ))
    }

    fn apply(&self, profile: &Profile, snapshot: &mut Snapshot) -> Result<(), BackendError> {
        if !Self::supports_profile(profile) {
            return Err(BackendError::ApplyFailed(
                "yerel proxy sahte paket veya TTL tekniği uygulayamaz".into(),
            ));
        }

        let mut slot = self
            .running
            .lock()
            .map_err(|_| BackendError::ApplyFailed("motor kilidi bozuldu".into()))?;
        if slot.is_some() {
            return Err(BackendError::Conflict("proxy zaten çalışıyor".into()));
        }

        let config = ProxyConfig {
            fragmentation: profile.strategy.fragmentation,
            ..self.config.clone()
        };
        let handle = server::start(config).map_err(|e| BackendError::ApplyFailed(e.to_string()))?;

        // Dinleyici bu oturuma ait bir kaynaktır; temizlik listesine girer.
        snapshot.record(snapshot.session.object_name("proxy_listener"));
        *slot = Some(handle);
        Ok(())
    }

    fn verify(&self) -> Result<HealthReport, BackendError> {
        let slot = self
            .running
            .lock()
            .map_err(|_| BackendError::VerifyFailed)?;
        let handle = slot.as_ref().ok_or(BackendError::VerifyFailed)?;

        let stats = handle.stats();
        let accepted = stats.accepted.load(Ordering::Relaxed);
        let failed = stats.failed.load(Ordering::Relaxed);

        // Henüz trafik geçmediyse sağlık hakkında bir şey söyleyemeyiz.
        // "Ölçemedik" ile "sorun yok" aynı şey değildir.
        if accepted == 0 {
            return Ok(HealthReport::new(
                ScoreInputs::default(),
                Classification::Unknown,
            ));
        }

        let success = (accepted.saturating_sub(failed)) as f64 / accepted as f64;
        Ok(HealthReport::new(
            ScoreInputs {
                availability: success,
                handshake_success: success,
                http_success: success,
                latency_health: 1.0,
                reset_health: success,
                loss_health: 1.0,
                dns_integrity: 1.0,
                // QUIC bu motorda taşınmaz; puan verilmez.
                quic_success: 0.0,
            },
            if success > 0.5 {
                Classification::Healthy
            } else {
                Classification::Degraded
            },
        ))
    }

    fn stop(&self, _snapshot: Snapshot) -> Result<(), BackendError> {
        let mut slot = self
            .running
            .lock()
            .map_err(|_| BackendError::RollbackFailed("motor kilidi bozuldu".into()))?;
        if let Some(handle) = slot.take() {
            handle.stop();
        }
        Ok(())
    }

    fn rollback(&self, snapshot: Snapshot) -> Result<(), BackendError> {
        // Bu motor kalıcı sistem durumu bırakmaz; geri alma temiz kapanıştır.
        self.stop(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::Duration;
    use trdpi_core::profile::FragmentationMode;

    fn profile(fragmentation: FragmentationMode) -> Profile {
        let mut p = Profile::baseline();
        p.strategy.fragmentation = fragmentation;
        p.supported_mechanisms = vec![Mechanism::LocalProxy];
        p
    }

    #[test]
    fn yetenekler_durustce_bildiriliyor() {
        let engine = ProxyEngine::default();
        let caps = engine.capabilities();

        assert!(!caps.privilege_escalation, "yetki istemiyoruz");
        assert!(!caps.quic_handling, "SOCKS5 UDP taşımıyor");
        assert!(!engine.mechanism().is_system_wide(), "kapsam sınırlı");
        assert!(!engine.mechanism().mutates_system());
    }

    #[test]
    fn yapamayacagi_teknik_reddediliyor() {
        let mut p = profile(FragmentationMode::SniAware);
        p.strategy.fake_traffic = FakeTrafficMode::Fake;
        assert!(!ProxyEngine::supports_profile(&p));

        let engine = ProxyEngine::default();
        let mut snap = engine.prepare(SessionId::new()).unwrap();
        let err = engine.apply(&p, &mut snap).unwrap_err();

        assert!(matches!(err, BackendError::ApplyFailed(_)));
        assert!(snap.is_empty(), "başarısız apply kaynak kaydetmemeli");
    }

    #[test]
    fn ttl_teknigi_de_reddediliyor() {
        let mut p = profile(FragmentationMode::Off);
        p.strategy.ttl = TtlMode::Auto;
        assert!(!ProxyEngine::supports_profile(&p));
    }

    #[test]
    fn trafik_gecmeden_saglik_bilinmiyor() {
        let engine = ProxyEngine::default();
        let mut snap = engine.prepare(SessionId::new()).unwrap();
        engine
            .apply(&profile(FragmentationMode::Off), &mut snap)
            .unwrap();

        let report = engine.verify().unwrap();
        assert_eq!(
            report.classification,
            Classification::Unknown,
            "ölçüm yokluğu sağlık kanıtı değil"
        );

        engine.stop(snap).unwrap();
    }

    #[test]
    fn dinleyici_snapshota_kaydediliyor() {
        let engine = ProxyEngine::default();
        let session = SessionId::new();
        let mut snap = engine.prepare(session.clone()).unwrap();

        engine
            .apply(&profile(FragmentationMode::Off), &mut snap)
            .unwrap();
        assert_eq!(snap.owned_objects.len(), 1);
        assert!(session.owns(&snap.owned_objects[0]));

        engine.stop(snap).unwrap();
    }

    #[test]
    fn iki_kez_baslatilamaz() {
        let engine = ProxyEngine::default();
        let mut snap = engine.prepare(SessionId::new()).unwrap();
        engine
            .apply(&profile(FragmentationMode::Off), &mut snap)
            .unwrap();

        let mut snap2 = engine.prepare(SessionId::new()).unwrap();
        let err = engine
            .apply(&profile(FragmentationMode::Off), &mut snap2)
            .unwrap_err();
        assert!(matches!(err, BackendError::Conflict(_)));

        engine.stop(snap).unwrap();
    }

    /// Uçtan uca: SOCKS5 üzerinden bir ClientHello gönder, hedef sunucunun
    /// onu **birden fazla okumada** aldığını doğrula.
    #[test]
    fn client_hello_gercekten_parcalanarak_gonderiliyor() {
        // Aldığı her okumayı kaydeden sahte hedef sunucu.
        let hedef = TcpListener::bind("127.0.0.1:0").unwrap();
        let hedef_adres = hedef.local_addr().unwrap();
        let (tx, rx) = mpsc::channel::<Vec<Vec<u8>>>();

        std::thread::spawn(move || {
            let (mut sock, _) = hedef.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(800)))
                .unwrap();

            let mut okumalar = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = sock.read(&mut buf) {
                if n == 0 {
                    break;
                }
                okumalar.push(buf[..n].to_vec());
            }
            let _ = tx.send(okumalar);
        });

        let engine = ProxyEngine::new(ProxyConfig {
            split_delay: Duration::from_millis(60),
            ..Default::default()
        });
        let mut snap = engine.prepare(SessionId::new()).unwrap();
        engine
            .apply(&profile(FragmentationMode::SniAware), &mut snap)
            .unwrap();
        let proxy_adres = engine.address().expect("proxy adresi yok");

        // SOCKS5 istemcisi
        let mut client = std::net::TcpStream::connect(proxy_adres).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut yanit = [0u8; 2];
        client.read_exact(&mut yanit).unwrap();
        assert_eq!(yanit, [0x05, 0x00]);

        let mut istek = vec![0x05, 0x01, 0x00, 0x01];
        istek.extend_from_slice(&[127, 0, 0, 1]);
        istek.extend_from_slice(&hedef_adres.port().to_be_bytes());
        client.write_all(&istek).unwrap();
        let mut yanit = [0u8; 10];
        client.read_exact(&mut yanit).unwrap();
        assert_eq!(yanit[1], 0x00, "SOCKS5 bağlantısı başarısız");

        let hello = clienthello::tests_support::client_hello("discord.com");
        client.write_all(&hello).unwrap();
        client.flush().unwrap();

        let okumalar = rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let toplam: Vec<u8> = okumalar.concat();
        assert_eq!(toplam, hello, "veri değişmiş");
        assert!(
            okumalar.len() >= 2,
            "ClientHello tek segmentte gitti, parçalama etkisiz: {} okuma",
            okumalar.len()
        );
        assert!(
            okumalar
                .iter()
                .all(|o| o.windows(11).all(|w| w != b"discord.com")),
            "bir segment SNI'ın tamamını taşıyor"
        );

        assert_eq!(engine.stats_fragmented(), 1);
        engine.stop(snap).unwrap();
    }

    impl ProxyEngine {
        fn stats_fragmented(&self) -> u64 {
            self.running
                .lock()
                .unwrap()
                .as_ref()
                .map(|h| h.stats().fragmented.load(Ordering::Relaxed))
                .unwrap_or(0)
        }
    }
}
