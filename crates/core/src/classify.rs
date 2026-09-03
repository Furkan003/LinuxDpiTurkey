//! Ağ davranışı sınıflandırması.
//!
//! Denetim B3: bu enum kaynak belgelerde üç farklı üyelikle geçiyordu
//! (`PASS` vs `HEALTHY`, `DNS_TAMPER` vs `DNS_TAMPERED`, `TIMEOUT` yalnız
//! birinde, `QUIC_BLOCKED`/`UNKNOWN` diğerinde). Buradaki tanım üçünün
//! birleşimidir ve tek normatif tanımdır.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Bir teşhis turunun sonucunda ağın durumu.
///
/// Sıra önemlidir: `Ord`, daha ciddi olan durumu daha büyük sayar; birden fazla
/// sinyal varsa en ciddi olanı raporlanır.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Müdahale belirtisi yok.
    Healthy,
    /// Çalışıyor ama beklenenden kötü; tek bir mekanizmaya atfedilemiyor.
    Degraded,
    /// Bağlantı kuruluyor ama olağandışı yavaş — hedefli kısıtlama belirtisi.
    Throttled,
    /// QUIC/UDP 443 erişilemiyor, TCP çalışıyor.
    QuicBlocked,
    /// Çözümleme sansürle ilişkili veya tutarsız adres döndürüyor.
    DnsTampered,
    /// TCP bağlantısı sıfırlanıyor.
    TcpReset,
    /// TLS handshake sırasında müdahale — genelde ilk write sonrası reset.
    TlsInterference,
    /// Yanıt hiç gelmiyor.
    Timeout,
    /// Yeterli sinyal toplanamadı.
    Unknown,
}

impl Classification {
    /// Sınıflandırmanın müdahale belirtisi taşıyıp taşımadığı.
    ///
    /// [`Classification::Unknown`] burada `false` döner: bilgi eksikliği,
    /// müdahale kanıtı değildir.
    pub fn is_interference(self) -> bool {
        matches!(
            self,
            Self::Throttled
                | Self::QuicBlocked
                | Self::DnsTampered
                | Self::TcpReset
                | Self::TlsInterference
        )
    }

    /// Kullanıcıya gösterilecek, teknik terim içermeyen açıklama.
    ///
    /// Ana ekranda yalnızca bu metin görünür; `nfqws`, `SNI`, `desync` gibi
    /// terimler Gelişmiş/Tanılama ekranına aittir.
    pub fn user_message(self) -> &'static str {
        match self {
            Self::Healthy => "Bağlantınızda engelleme belirtisi görünmüyor.",
            Self::Degraded => "Bağlantınız çalışıyor ama beklenenden kötü durumda.",
            Self::Throttled => "Bağlantınız kasıtlı olarak yavaşlatılıyor olabilir.",
            Self::QuicBlocked => "Bazı siteler için kullanılan yeni bağlantı yöntemi engelleniyor.",
            Self::DnsTampered => "Adres çözümlemenize müdahale ediliyor.",
            Self::TcpReset => "Bağlantınız kurulduktan hemen sonra kesiliyor.",
            Self::TlsInterference => "Güvenli bağlantı kurulurken müdahale belirtisi görüldü.",
            Self::Timeout => "Hedefe hiç ulaşılamıyor.",
            Self::Unknown => "Bağlantınız yeterince ölçülemedi.",
        }
    }

    /// Log ve IPC için sabit anahtar.
    pub fn as_key(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Throttled => "throttled",
            Self::QuicBlocked => "quic_blocked",
            Self::DnsTampered => "dns_tampered",
            Self::TcpReset => "tcp_reset",
            Self::TlsInterference => "tls_interference",
            Self::Timeout => "timeout",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Classification; 9] = [
        Classification::Healthy,
        Classification::Degraded,
        Classification::Throttled,
        Classification::QuicBlocked,
        Classification::DnsTampered,
        Classification::TcpReset,
        Classification::TlsInterference,
        Classification::Timeout,
        Classification::Unknown,
    ];

    #[test]
    fn serde_anahtarlari_as_key_ile_ayni() {
        for c in ALL {
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(json, format!("\"{}\"", c.as_key()));
            assert_eq!(serde_json::from_str::<Classification>(&json).unwrap(), c);
        }
    }

    #[test]
    fn healthy_en_hafif_unknown_en_agir() {
        let mut sorted = ALL;
        sorted.sort();
        assert_eq!(sorted[0], Classification::Healthy);
        assert_eq!(*sorted.last().unwrap(), Classification::Unknown);
    }

    #[test]
    fn bilgi_eksikligi_mudahale_sayilmaz() {
        assert!(!Classification::Unknown.is_interference());
        assert!(!Classification::Healthy.is_interference());
        assert!(Classification::TlsInterference.is_interference());
    }

    #[test]
    fn her_durumun_kullanici_metni_var_ve_teknik_terim_icermiyor() {
        for c in ALL {
            let msg = c.user_message();
            assert!(!msg.is_empty());
            let lower = msg.to_lowercase();
            for jargon in [
                "nfqws",
                "nftables",
                "sni",
                "desync",
                "windivert",
                "iptables",
            ] {
                assert!(
                    !lower.contains(jargon),
                    "{c}: '{jargon}' kullanıcıya gösterilemez"
                );
            }
        }
    }
}
