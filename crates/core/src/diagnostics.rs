//! Teşhis sonuç tipleri.
//!
//! Ölçümün *nasıl* yapıldığı `trdpi-diagnostics` crate'ine aittir; burada
//! yalnızca sonuç şekli tanımlıdır, böylece politika mantığı gerçek ağ olmadan
//! test edilebilir.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::classify::Classification;

/// Yapılan ölçümün türü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticKind {
    /// Çözümlemenin tutarlılığı.
    DnsIntegrity,
    /// TCP bağlantısı kurulabiliyor mu.
    TcpConnect,
    /// TLS handshake tamamlanıyor mu.
    TlsHandshake,
    /// Beklenen HTTP yanıtı alınıyor mu.
    HttpFetch,
    /// QUIC/UDP 443 erişilebilir mi.
    QuicReachability,
    /// Gerçek zamanlı UDP yolu (oyun, sesli görüşme) açık mı.
    ///
    /// Yüksek portlarda akar ve QUIC'ten ayrı ölçülür: 443 kapalıyken bu
    /// yol açık olabilir, tersi de mümkündür.
    RealtimeUdp,
}

/// Tek bir ölçümün sonucu.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticResult {
    /// Ölçüm türü.
    pub kind: DiagnosticKind,
    /// Ölçümün yapıldığı hedef.
    pub target: String,
    /// Başarılı mı.
    pub success: bool,
    /// Süre — ölçülemediyse `None`.
    pub latency: Option<Duration>,
    /// Bu ölçümün işaret ettiği davranış.
    pub classification: Classification,
    /// Kullanıcıya gösterilmeyen teknik ayrıntı.
    ///
    /// Gizlilik: buraya trafik içeriği, payload veya tam gezinme geçmişi
    /// yazılmaz — yalnızca ölçüme ait teknik özet.
    pub detail: Option<String>,
}

impl DiagnosticResult {
    /// Başarılı bir ölçüm.
    pub fn ok(kind: DiagnosticKind, target: impl Into<String>, latency: Duration) -> Self {
        Self {
            kind,
            target: target.into(),
            success: true,
            latency: Some(latency),
            classification: Classification::Healthy,
            detail: None,
        }
    }

    /// Başarısız bir ölçüm.
    pub fn failed(
        kind: DiagnosticKind,
        target: impl Into<String>,
        classification: Classification,
    ) -> Self {
        Self {
            kind,
            target: target.into(),
            success: false,
            latency: None,
            classification,
            detail: None,
        }
    }

    /// Teknik ayrıntı ekler.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Bir ağın gözlenen davranış imzası.
///
/// Denetim P §38: profil seçimi ISP adına değil bu imzaya göre yapılır. `asn`
/// yalnızca arayüzde gösterilir ve tek başına karar girdisi değildir.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkFingerprint {
    /// Otonom sistem numarası — yalnızca gösterim.
    pub asn: Option<u32>,
    /// Ağ etiketi — yalnızca gösterim.
    pub network_label: Option<String>,
    /// DNS'e müdahale gözlendi mi.
    pub dns_tampering: bool,
    /// TLS handshake sırasında reset gözlendi mi.
    pub tls_reset: bool,
    /// TCP reset gözlendi mi.
    pub tcp_reset: bool,
    /// Kısıtlama belirtisi var mı.
    pub throttling: bool,
    /// QUIC engellenmiş mi.
    pub quic_blocked: bool,
    /// IPv6 kullanılabilir mi.
    pub ipv6_available: bool,
}

impl NetworkFingerprint {
    /// Ölçüm sonuçlarından imza çıkarır.
    pub fn from_results(results: &[DiagnosticResult]) -> Self {
        let saw = |c: Classification| results.iter().any(|r| r.classification == c);
        Self {
            dns_tampering: saw(Classification::DnsTampered),
            tls_reset: saw(Classification::TlsInterference),
            tcp_reset: saw(Classification::TcpReset),
            throttling: saw(Classification::Throttled),
            quic_blocked: saw(Classification::QuicBlocked),
            ..Default::default()
        }
    }

    /// Hiçbir müdahale belirtisi yok mu.
    pub fn is_clean(&self) -> bool {
        !(self.dns_tampering
            || self.tls_reset
            || self.tcp_reset
            || self.throttling
            || self.quic_blocked)
    }

    /// Gözlenen en ciddi davranış.
    ///
    /// Ölçüm yoksa [`Classification::Unknown`] döner — "sorun yok" değil.
    pub fn overall(results: &[DiagnosticResult]) -> Classification {
        results
            .iter()
            .map(|r| r.classification)
            .max()
            .unwrap_or(Classification::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(kind: DiagnosticKind, c: Classification) -> DiagnosticResult {
        DiagnosticResult::failed(kind, "ornek.test", c)
    }

    #[test]
    fn temiz_ag_temiz_imza_veriyor() {
        let results = vec![DiagnosticResult::ok(
            DiagnosticKind::TlsHandshake,
            "ornek.test",
            Duration::from_millis(43),
        )];
        let fp = NetworkFingerprint::from_results(&results);
        assert!(fp.is_clean());
        assert_eq!(
            NetworkFingerprint::overall(&results),
            Classification::Healthy
        );
    }

    #[test]
    fn imza_gozlenen_sinyalleri_yakaliyor() {
        let results = vec![
            res(DiagnosticKind::DnsIntegrity, Classification::DnsTampered),
            res(
                DiagnosticKind::TlsHandshake,
                Classification::TlsInterference,
            ),
        ];
        let fp = NetworkFingerprint::from_results(&results);
        assert!(fp.dns_tampering && fp.tls_reset);
        assert!(!fp.quic_blocked);
        assert!(!fp.is_clean());
    }

    #[test]
    fn en_ciddi_davranis_raporlaniyor() {
        let results = vec![
            res(
                DiagnosticKind::QuicReachability,
                Classification::QuicBlocked,
            ),
            res(
                DiagnosticKind::TlsHandshake,
                Classification::TlsInterference,
            ),
            res(DiagnosticKind::HttpFetch, Classification::Degraded),
        ];
        assert_eq!(
            NetworkFingerprint::overall(&results),
            Classification::TlsInterference
        );
    }

    /// Ölçüm yokluğu "sorun yok" anlamına gelmez.
    #[test]
    fn olcum_yoksa_unknown() {
        assert_eq!(NetworkFingerprint::overall(&[]), Classification::Unknown);
    }

    #[test]
    fn sonuc_json_gidip_geliyor() {
        let r = DiagnosticResult::ok(
            DiagnosticKind::TcpConnect,
            "ornek.test:443",
            Duration::from_millis(12),
        )
        .with_detail("3 deneme");
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<DiagnosticResult>(&json).unwrap(), r);
    }
}
