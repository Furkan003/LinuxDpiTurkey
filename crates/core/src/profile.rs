//! Strateji profili.
//!
//! Denetim A1: kaynak belgelerde `Profile` dört farklı biçimde tanımlanmıştı.
//! Bu, tek normatif tanımdır. Çözülen çelişkiler:
//!
//! - `fragment`/`fragmentation`, `fake_packets`/`fake_traffic`,
//!   `header_normalization`/`header_strategy` → tek isim.
//! - `quic` bir kaynakta `protocols`, diğerinde `strategy` altındaydı. Karar:
//!   **`protocols` kapsamı, `strategy` tekniği tanımlar.** QUIC'e dokunulup
//!   dokunulmayacağı bir kapsam sorusudur, bu yüzden [`ProtocolPolicy`] içinde.
//! - `platform: String` kaldırıldı; yerine [`Profile::supported_mechanisms`],
//!   ki platformu zaten ima eder ve stringly-typed değildir.
//! - `version` eklendi (Kural 10: versioned local profile store).
//! - `description` ve `supported_mechanisms` yalnız bir kaynakta vardı; eklendi.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::{Capabilities, Mechanism};

/// Profil kimliği.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProfileId(String);

impl ProfileId {
    /// Kimliği doğrulayarak sarmalar.
    ///
    /// Profil kimlikleri dosya adı ve log anahtarı olarak kullanıldığı için
    /// yalnızca `[a-z0-9-]` kabul edilir.
    pub fn parse(raw: &str) -> Result<Self, InvalidProfileId> {
        let ok = !raw.is_empty()
            && raw.len() <= 64
            && raw
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !raw.starts_with('-')
            && !raw.ends_with('-');
        if ok {
            Ok(ProfileId(raw.to_owned()))
        } else {
            Err(InvalidProfileId)
        }
    }

    /// Ham kimlik.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// [`ProfileId::parse`] geçersiz girdi aldığında döner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("geçersiz profil kimliği: yalnızca küçük harf, rakam ve tire")]
pub struct InvalidProfileId;

/// Profilin bağlantı kalitesini bozma riski.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Yan etkisi beklenmeyen teknikler.
    Low,
    /// Bazı sitelerde yavaşlama olabilir.
    Medium,
    /// Bağlantı kalitesini gözle görülür bozabilir.
    High,
}

/// DNS'e nasıl davranılacağı.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// Dokunma.
    System,
    /// Uygulama içi şifreli çözümleyici kullan.
    Encrypted,
}

/// QUIC/UDP 443'e nasıl davranılacağı.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicMode {
    /// Dokunma.
    Passthrough,
    /// QUIC üzerinde de desync uygula.
    Desync,
    /// QUIC'i kapat, uygulamalar TCP'ye düşsün.
    ///
    /// Performansı düşürür ve bazı uygulamaları bozabilir; bu yüzden bunu
    /// kullanan profiller [`RiskLevel::High`] olmalıdır.
    Block,
}

/// Parçalama tekniği.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FragmentationMode {
    /// Kapalı.
    Off,
    /// Sabit konumdan böl.
    Fixed {
        /// Bölme konumu (bayt).
        position: u16,
    },
    /// SNI konumuna göre böl.
    SniAware,
}

/// Sahte trafik tekniği.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FakeTrafficMode {
    /// Kapalı.
    Off,
    /// Gerçek paketten önce sahte paket gönder.
    Fake,
    /// Sahte paketi sıra dışı gönder.
    Disorder,
}

/// Sahte paketlerin TTL'i.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TtlMode {
    /// TTL ile oynama.
    Off,
    /// Sabit TTL.
    Fixed {
        /// TTL değeri.
        hops: u8,
    },
    /// Ölçülen yol uzunluğundan türet.
    Auto,
}

/// HTTP başlık biçimi müdahalesi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderStrategy {
    /// Dokunma.
    Off,
    /// `Host` başlığının harf büyüklüğünü değiştir.
    HostCase,
}

/// Profilin hangi katmanlara dokunduğu — **kapsam**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolPolicy {
    /// DNS davranışı.
    pub dns: DnsMode,
    /// TCP katmanına dokunulsun mu.
    pub tcp: bool,
    /// TLS katmanına dokunulsun mu.
    pub tls: bool,
    /// QUIC davranışı.
    pub quic: QuicMode,
}

/// Kapsam içindeki katmanlara nasıl dokunulduğu — **teknik**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyPolicy {
    /// Parçalama.
    pub fragmentation: FragmentationMode,
    /// Sahte trafik.
    pub fake_traffic: FakeTrafficMode,
    /// TTL.
    pub ttl: TtlMode,
    /// Başlık biçimi.
    pub header: HeaderStrategy,
}

/// Profilin başarılı sayılma koşulu.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HealthPolicy {
    /// Bu profilin kalıcı sayılması için gereken en düşük skor.
    pub success_threshold: f64,
    /// Bu skorun altına düşülürse kurtarma başlar.
    pub degraded_threshold: f64,
}

impl Default for HealthPolicy {
    fn default() -> Self {
        Self {
            success_threshold: 0.82,
            degraded_threshold: 0.60,
        }
    }
}

/// Bir strateji profili.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// Kimlik.
    pub id: ProfileId,
    /// Şema sürümü — yerel profil deposu sürümlüdür.
    pub version: u32,
    /// Arayüzde görünen ad.
    pub name: String,
    /// Bir cümlelik açıklama.
    pub description: String,
    /// Bağlantıyı bozma riski.
    pub risk: RiskLevel,
    /// Bu profilin çalışabileceği mekanizmalar.
    pub supported_mechanisms: Vec<Mechanism>,
    /// Kapsam.
    pub protocols: ProtocolPolicy,
    /// Teknik.
    pub strategy: StrategyPolicy,
    /// Başarı koşulu.
    pub health: HealthPolicy,
}

impl Profile {
    /// Geçerli olduğunu doğrular.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.supported_mechanisms.is_empty() {
            return Err(ProfileError::NoMechanism);
        }
        let h = &self.health;
        for t in [h.success_threshold, h.degraded_threshold] {
            if !(0.0..=1.0).contains(&t) || t.is_nan() {
                return Err(ProfileError::ThresholdRange);
            }
        }
        if h.degraded_threshold > h.success_threshold {
            return Err(ProfileError::ThresholdOrder);
        }
        // QUIC'i tamamen kapatmak kullanıcının göreceği bir bozulmadır;
        // düşük riskli diye etiketlenemez.
        if self.protocols.quic == QuicMode::Block && self.risk == RiskLevel::Low {
            return Err(ProfileError::UnderstatedRisk);
        }
        Ok(())
    }

    /// Bu profilin verilen yeteneklerle çalıştırılabilir olup olmadığı.
    pub fn is_runnable_with(&self, caps: &Capabilities) -> bool {
        let best = caps.best_mechanism();
        self.supported_mechanisms.contains(&best)
    }

    /// Sistemi hiç değiştirmeyen, yalnızca ölçüm yapan taban profil.
    ///
    /// Her teşhis turu buradan başlar (S0 — direct baseline).
    pub fn baseline() -> Self {
        Profile {
            id: ProfileId("baseline-direct".into()),
            version: 1,
            name: "Müdahalesiz".into(),
            description: "Hiçbir değişiklik yapmadan bağlantıyı ölçer.".into(),
            risk: RiskLevel::Low,
            supported_mechanisms: Mechanism::PREFERENCE.to_vec(),
            protocols: ProtocolPolicy {
                dns: DnsMode::System,
                tcp: false,
                tls: false,
                quic: QuicMode::Passthrough,
            },
            strategy: StrategyPolicy {
                fragmentation: FragmentationMode::Off,
                fake_traffic: FakeTrafficMode::Off,
                ttl: TtlMode::Off,
                header: HeaderStrategy::Off,
            },
            health: HealthPolicy::default(),
        }
    }
}

/// Profil doğrulama hataları.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// Hiçbir mekanizma listelenmemiş.
    #[error("profil hiçbir mekanizmayı desteklemiyor")]
    NoMechanism,
    /// Eşik 0.0–1.0 dışında.
    #[error("sağlık eşikleri 0.0–1.0 aralığında olmalı")]
    ThresholdRange,
    /// Bozulma eşiği başarı eşiğinden büyük.
    #[error("degraded_threshold, success_threshold'dan büyük olamaz")]
    ThresholdOrder,
    /// Risk seviyesi tekniğin gerçek etkisini olduğundan hafif gösteriyor.
    #[error("QUIC'i kapatan profil düşük riskli olarak etiketlenemez")]
    UnderstatedRisk,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taban_profil_gecerli_ve_hicbir_seye_dokunmuyor() {
        let p = Profile::baseline();
        assert!(p.validate().is_ok());
        assert!(!p.protocols.tcp && !p.protocols.tls);
        assert_eq!(p.protocols.quic, QuicMode::Passthrough);
        assert_eq!(p.strategy.fragmentation, FragmentationMode::Off);
    }

    #[test]
    fn profil_json_gidip_geliyor() {
        let p = Profile::baseline();
        let json = serde_json::to_string_pretty(&p).unwrap();
        assert_eq!(serde_json::from_str::<Profile>(&json).unwrap(), p);
    }

    #[test]
    fn quic_kapatan_profil_dusuk_riskli_olamaz() {
        let mut p = Profile::baseline();
        p.protocols.quic = QuicMode::Block;
        assert_eq!(p.validate(), Err(ProfileError::UnderstatedRisk));

        p.risk = RiskLevel::High;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn esikler_dogrulaniyor() {
        let mut p = Profile::baseline();
        p.health.success_threshold = 1.5;
        assert_eq!(p.validate(), Err(ProfileError::ThresholdRange));

        p.health.success_threshold = 0.5;
        p.health.degraded_threshold = 0.9;
        assert_eq!(p.validate(), Err(ProfileError::ThresholdOrder));
    }

    #[test]
    fn mekanizmasiz_profil_reddediliyor() {
        let mut p = Profile::baseline();
        p.supported_mechanisms.clear();
        assert_eq!(p.validate(), Err(ProfileError::NoMechanism));
    }

    #[test]
    fn profil_kimligi_dogrulaniyor() {
        assert!(ProfileId::parse("tr-tls-balanced").is_ok());
        assert!(ProfileId::parse("").is_err());
        assert!(ProfileId::parse("-bas").is_err());
        assert!(ProfileId::parse("son-").is_err());
        assert!(ProfileId::parse("../etc").is_err());
        assert!(ProfileId::parse("Buyuk").is_err());
    }

    #[test]
    fn yetenek_uyusmazligi_yakalaniyor() {
        let only_proxy = Capabilities {
            mechanisms: vec![Mechanism::LocalProxy],
            ..Default::default()
        };
        let mut p = Profile::baseline();
        p.supported_mechanisms = vec![Mechanism::Nfqueue];
        assert!(!p.is_runnable_with(&only_proxy));

        p.supported_mechanisms.push(Mechanism::LocalProxy);
        assert!(p.is_runnable_with(&only_proxy));
    }
}
