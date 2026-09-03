//! Backend sözleşmesi.
//!
//! Denetim A2: kaynak belgelerde bu trait üç farklı imzayla tanımlıydı ve
//! "Teknik Şartname"deki sürümün `rollback` metodu snapshot parametresi
//! almıyordu — yani belgelerin kendi transaction modeli uygulanamıyordu.
//! Buradaki tanımda [`Backend::prepare`] bir [`Snapshot`] üretir ve
//! [`Backend::rollback`] onu geri almak için tüketir.
//!
//! Yaşam döngüsü:
//!
//! ```text
//! probe → prepare → apply → verify → (commit)
//!                     ↓ hata
//!                  rollback → verify_clean
//! ```

use serde::{Deserialize, Serialize};

use crate::capability::{Capabilities, Mechanism};
use crate::profile::Profile;
use crate::score::HealthReport;
use crate::session::SessionId;

/// Bir motorun kimliği.
///
/// [`Mechanism`] ile karıştırılmamalıdır: mekanizma paketi *nasıl* yakaladığımız,
/// motor *hangi mantığı* uyguladığımızdır. Aynı motor birden fazla mekanizma
/// üzerinde çalışabilir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineId {
    /// Kendi paket işleme motorumuz.
    Native,
    /// Kendi yerel proxy motorumuz.
    Proxy,
    /// Hiçbir motor; yalnızca ölçüm.
    None,
}

/// Uygulanan sistem değişikliklerinin geri alınabilir kaydı.
///
/// Snapshot **yalnızca uygulamanın kendi oluşturduğu objeleri** taşır. Başka
/// uygulamalara ait firewall kuralları ne yedeklenir ne de silinir.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Bu snapshot'ı üreten oturum.
    pub session: SessionId,
    /// Snapshot'ı üreten motor.
    pub engine: EngineId,
    /// Kullanılan mekanizma.
    pub mechanism: Mechanism,
    /// Uygulamanın oluşturduğu sistem objelerinin isimleri.
    pub owned_objects: Vec<String>,
}

impl Snapshot {
    /// Boş bir snapshot açar.
    pub fn new(session: SessionId, engine: EngineId, mechanism: Mechanism) -> Self {
        Self {
            session,
            engine,
            mechanism,
            owned_objects: Vec::new(),
        }
    }

    /// Oluşturulan bir sistem objesini kaydeder.
    ///
    /// İsim bu oturuma ait değilse kaydedilmez ve `false` döner — böylece
    /// yabancı bir obje yanlışlıkla temizlik listesine giremez.
    pub fn record(&mut self, object_name: impl Into<String>) -> bool {
        let name = object_name.into();
        if !self.session.owns(&name) {
            return false;
        }
        if !self.owned_objects.contains(&name) {
            self.owned_objects.push(name);
        }
        true
    }

    /// Geri alınacak bir şey var mı.
    pub fn is_empty(&self) -> bool {
        self.owned_objects.is_empty()
    }
}

/// Bir backend'in probe aşamasına verilen bağlam.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeContext {
    /// Tespit edilen sistem yetenekleri.
    pub capabilities: Capabilities,
    /// Bu oturum için üretilmiş kimlik.
    pub session: SessionId,
}

/// Bir backend'in kendini çalıştırılabilir görüp görmediği.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Çalıştırılabilir mi.
    pub usable: bool,
    /// Kullanacağı mekanizma.
    pub mechanism: Mechanism,
    /// Kullanılamıyorsa sebebi.
    pub reason: Option<String>,
}

impl ProbeResult {
    /// Kullanılabilir sonuç.
    pub fn usable(mechanism: Mechanism) -> Self {
        Self {
            usable: true,
            mechanism,
            reason: None,
        }
    }

    /// Kullanılamaz sonuç.
    pub fn unusable(mechanism: Mechanism, reason: impl Into<String>) -> Self {
        Self {
            usable: false,
            mechanism,
            reason: Some(reason.into()),
        }
    }
}

/// Trafiğe müdahale eden bir motorun sözleşmesi.
///
/// Uygulayanlar için kurallar:
///
/// 1. [`Backend::apply`] çağrılmadan önce [`Backend::prepare`] çağrılmış olmalıdır.
/// 2. Oluşturulan her sistem objesi snapshot'a kaydedilmelidir.
/// 3. [`Backend::rollback`] yalnızca snapshot'taki objelere dokunur.
/// 4. Hiçbir metot kullanıcıya terminal komutu önermez; hatalar
///    [`BackendError`] olarak döner.
pub trait Backend: Send + Sync {
    /// Motor kimliği.
    fn id(&self) -> EngineId;

    /// Bu motorun kullandığı mekanizma.
    fn mechanism(&self) -> Mechanism;

    /// Bu motorun sağladığı yetenekler.
    fn capabilities(&self) -> Capabilities;

    /// Çalıştırılabilir mi — sistemi değiştirmez.
    fn probe(&self, ctx: &ProbeContext) -> Result<ProbeResult, BackendError>;

    /// Uygulamaya hazırlanır ve geri alma kaydını açar.
    fn prepare(&self, session: SessionId) -> Result<Snapshot, BackendError>;

    /// Profili uygular; oluşturduğu her objeyi snapshot'a yazar.
    fn apply(&self, profile: &Profile, snapshot: &mut Snapshot) -> Result<(), BackendError>;

    /// Uygulanan durumu ölçer.
    fn verify(&self) -> Result<HealthReport, BackendError>;

    /// Temiz kapanış.
    fn stop(&self, snapshot: Snapshot) -> Result<(), BackendError>;

    /// Snapshot'taki değişiklikleri geri alır.
    ///
    /// Başarısız olursa [`BackendError::RollbackFailed`] döner; çağıran bunu
    /// kullanıcıya "ağ kurtarma" akışı olarak göstermelidir.
    fn rollback(&self, snapshot: Snapshot) -> Result<(), BackendError>;
}

/// Backend hataları.
///
/// Her varyantın kullanıcıya gösterilebilir bir karşılığı vardır
/// ([`BackendError::user_message`]); hiçbiri kullanıcıdan terminal komutu
/// çalıştırmasını istemez.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// Yetki istendi ama verilmedi.
    #[error("yetki verilmedi")]
    PrivilegeDenied,
    /// Gerekli çekirdek/sistem yeteneği yok.
    #[error("gerekli sistem yeteneği yok: {0}")]
    MissingCapability(&'static str),
    /// Uygulama sırasında hata.
    #[error("uygulanamadı: {0}")]
    ApplyFailed(String),
    /// Doğrulama eşiği tutmadı.
    #[error("doğrulama başarısız")]
    VerifyFailed,
    /// Geri alma başarısız — sistem yarı yapılandırılmış olabilir.
    #[error("geri alınamadı: {0}")]
    RollbackFailed(String),
    /// Başka bir ağ aracıyla çakışma.
    #[error("çakışan yapılandırma: {0}")]
    Conflict(String),
}

impl BackendError {
    /// Kullanıcıya gösterilecek metin.
    pub fn user_message(&self) -> String {
        match self {
            Self::PrivilegeDenied => {
                "Yönetici yetkisi verilmedi. Sistem geneli mod yerine yerel mod kullanılabilir."
                    .into()
            }
            Self::MissingCapability(_) => {
                "Bu sistemde sistem geneli koruma kullanılamıyor. Yerel mod kullanılabilir.".into()
            }
            Self::ApplyFailed(_) => {
                "Seçilen yöntem uygulanamadı. Başka bir yöntem deneniyor.".into()
            }
            Self::VerifyFailed => {
                "Bu yöntem bağlantınızı düzeltmedi. Başka bir yöntem deneniyor.".into()
            }
            Self::RollbackFailed(_) => {
                "Ağ ayarlarınız eski haline getirilemedi. Kurtarma ekranı açılıyor.".into()
            }
            Self::Conflict(_) => {
                "Başka bir ağ aracı çalışıyor. Çakışmayı gidermeden devam edilemiyor.".into()
            }
        }
    }

    /// Başka bir profille yeniden denemenin anlamlı olup olmadığı.
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Self::ApplyFailed(_) | Self::VerifyFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_yalnizca_kendi_objesini_kaydediyor() {
        let session = SessionId::new();
        let mut snap = Snapshot::new(session.clone(), EngineId::Native, Mechanism::Nfqueue);

        assert!(snap.record(session.object_name("nft_table")));
        assert!(!snap.record("docker0"), "yabancı obje kaydedilemez");
        assert!(!snap.record("ufw-before-input"));

        assert_eq!(snap.owned_objects.len(), 1);
    }

    #[test]
    fn ayni_obje_iki_kez_kaydedilmiyor() {
        let session = SessionId::new();
        let mut snap = Snapshot::new(session.clone(), EngineId::Native, Mechanism::Nfqueue);
        let name = session.object_name("proxy");

        snap.record(name.clone());
        snap.record(name);
        assert_eq!(snap.owned_objects.len(), 1);
    }

    #[test]
    fn baska_oturumun_objesi_kaydedilmiyor() {
        let mine = SessionId::new();
        let other = SessionId::new();
        let mut snap = Snapshot::new(mine, EngineId::Native, Mechanism::Nfqueue);

        assert!(!snap.record(other.object_name("nft_table")));
        assert!(snap.is_empty());
    }

    #[test]
    fn her_hatanin_kullanici_metni_var_ve_komut_onermiyor() {
        let errors = [
            BackendError::PrivilegeDenied,
            BackendError::MissingCapability("nfqueue"),
            BackendError::ApplyFailed("x".into()),
            BackendError::VerifyFailed,
            BackendError::RollbackFailed("x".into()),
            BackendError::Conflict("x".into()),
        ];
        for e in errors {
            let msg = e.user_message();
            assert!(!msg.is_empty());
            for forbidden in ["sudo", "nft ", "iptables", "systemctl", "terminal"] {
                assert!(
                    !msg.to_lowercase().contains(forbidden),
                    "{e:?} kullanıcıya komut öneriyor"
                );
            }
        }
    }

    #[test]
    fn geri_alma_hatasi_kurtarilabilir_degil() {
        assert!(!BackendError::RollbackFailed("x".into()).is_recoverable());
        assert!(!BackendError::PrivilegeDenied.is_recoverable());
        assert!(BackendError::VerifyFailed.is_recoverable());
    }

    #[test]
    fn snapshot_json_gidip_geliyor() {
        let session = SessionId::new();
        let mut snap = Snapshot::new(session.clone(), EngineId::Native, Mechanism::Nfqueue);
        snap.record(session.object_name("nft_table"));

        let json = serde_json::to_string(&snap).unwrap();
        assert_eq!(serde_json::from_str::<Snapshot>(&json).unwrap(), snap);
    }
}
