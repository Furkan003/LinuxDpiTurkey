//! Sağlık skoru.
//!
//! Denetim B2: kaynak belgelerde iki uyumsuz model vardı — bir ağırlıklı toplam
//! (P §15.2) ve profil içinde tanımı belirsiz `latency_penalty` /
//! `packet_loss_penalty` değerleri. Burada tek model var: her bileşen 0..=1
//! aralığında normalize edilir, ağırlıklarla toplanır, ağırlıklar toplamı 1.0'dır
//! (test bunu zorlar). "Penalty" ayrı bir kavram değildir; gecikme ve kayıp
//! kendi bileşenleri olarak girer.

use serde::{Deserialize, Serialize};

use crate::classify::Classification;

/// 0.0 – 1.0 aralığında sağlık skoru.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct HealthScore(f64);

impl HealthScore {
    /// Verilen değeri 0.0–1.0 aralığına kırparak sarmalar.
    pub fn new(value: f64) -> Self {
        HealthScore(if value.is_nan() {
            0.0
        } else {
            value.clamp(0.0, 1.0)
        })
    }

    /// Ham değer.
    pub fn get(self) -> f64 {
        self.0
    }

    /// Arayüzde gösterilen 0–100 arası tam sayı.
    pub fn percent(self) -> u8 {
        (self.0 * 100.0).round() as u8
    }
}

/// Skora giren ham ölçümler. Hepsi 0.0–1.0 aralığında normalize edilmiş olmalıdır.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct ScoreInputs {
    /// Hedeflere hiç ulaşılabiliyor mu.
    pub availability: f64,
    /// TLS handshake başarı oranı.
    pub handshake_success: f64,
    /// Beklenen HTTP yanıtı alma oranı.
    pub http_success: f64,
    /// QUIC erişilebilirliği.
    pub quic_success: f64,
    /// Gecikme iyiliği — 1.0 hızlı, 0.0 çok yavaş.
    pub latency_health: f64,
    /// Reset oranının tersi — 1.0 hiç reset yok.
    pub reset_health: f64,
    /// Paket kaybının tersi — 1.0 kayıp yok.
    pub loss_health: f64,
    /// DNS yanıtlarının tutarlılığı.
    pub dns_integrity: f64,
}

/// Bileşen ağırlıkları. Toplamları daima 1.0'dır.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ScoreWeights {
    /// [`ScoreInputs::availability`] ağırlığı.
    pub availability: f64,
    /// [`ScoreInputs::handshake_success`] ağırlığı.
    pub handshake_success: f64,
    /// [`ScoreInputs::http_success`] ağırlığı.
    pub http_success: f64,
    /// [`ScoreInputs::quic_success`] ağırlığı.
    pub quic_success: f64,
    /// [`ScoreInputs::latency_health`] ağırlığı.
    pub latency_health: f64,
    /// [`ScoreInputs::reset_health`] ağırlığı.
    pub reset_health: f64,
    /// [`ScoreInputs::loss_health`] ağırlığı.
    pub loss_health: f64,
    /// [`ScoreInputs::dns_integrity`] ağırlığı.
    pub dns_integrity: f64,
}

impl ScoreWeights {
    /// Başlangıç ağırlıkları.
    ///
    /// Gerçek ölçümlerle yeniden kalibre edilmelidir; bu değerler tahmindir.
    pub const DEFAULT: ScoreWeights = ScoreWeights {
        availability: 0.28,
        handshake_success: 0.18,
        http_success: 0.14,
        quic_success: 0.08,
        latency_health: 0.10,
        reset_health: 0.10,
        loss_health: 0.07,
        dns_integrity: 0.05,
    };

    /// Ağırlıkların toplamı. Sözleşme gereği 1.0 olmalıdır.
    pub fn sum(&self) -> f64 {
        self.availability
            + self.handshake_success
            + self.http_success
            + self.quic_success
            + self.latency_health
            + self.reset_health
            + self.loss_health
            + self.dns_integrity
    }
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Ölçümleri tek bir skora indirger.
///
/// Bu, ürünün **tek** skorlama fonksiyonudur; hem taban teşhis hem aday profil
/// değerlendirmesi bunu kullanır.
pub fn score(inputs: &ScoreInputs, weights: &ScoreWeights) -> HealthScore {
    let n = |v: f64| if v.is_nan() { 0.0 } else { v.clamp(0.0, 1.0) };
    HealthScore::new(
        n(inputs.availability) * weights.availability
            + n(inputs.handshake_success) * weights.handshake_success
            + n(inputs.http_success) * weights.http_success
            + n(inputs.quic_success) * weights.quic_success
            + n(inputs.latency_health) * weights.latency_health
            + n(inputs.reset_health) * weights.reset_health
            + n(inputs.loss_health) * weights.loss_health
            + n(inputs.dns_integrity) * weights.dns_integrity,
    )
}

/// Bir doğrulama turunun çıktısı.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthReport {
    /// Toplam skor.
    pub score: HealthScore,
    /// Skoru üreten ham ölçümler.
    pub inputs: ScoreInputs,
    /// En ciddi gözlenen davranış.
    pub classification: Classification,
}

impl HealthReport {
    /// Ölçümlerden rapor üretir.
    pub fn new(inputs: ScoreInputs, classification: Classification) -> Self {
        Self {
            score: score(&inputs, &ScoreWeights::DEFAULT),
            inputs,
            classification,
        }
    }

    /// Skorun verilen eşiği geçip geçmediği.
    pub fn meets(&self, threshold: f64) -> bool {
        self.score.get() >= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perfect() -> ScoreInputs {
        ScoreInputs {
            availability: 1.0,
            handshake_success: 1.0,
            http_success: 1.0,
            quic_success: 1.0,
            latency_health: 1.0,
            reset_health: 1.0,
            loss_health: 1.0,
            dns_integrity: 1.0,
        }
    }

    /// Denetim B2'nin gerileme testi.
    #[test]
    fn agirliklar_toplami_bir() {
        assert!((ScoreWeights::DEFAULT.sum() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn mukemmel_olcum_tam_puan() {
        assert!((score(&perfect(), &ScoreWeights::DEFAULT).get() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn sifir_olcum_sifir_puan() {
        assert_eq!(
            score(&ScoreInputs::default(), &ScoreWeights::DEFAULT).get(),
            0.0
        );
    }

    #[test]
    fn bozuk_girdi_paniklemiyor() {
        let bad = ScoreInputs {
            availability: f64::NAN,
            handshake_success: f64::INFINITY,
            http_success: -5.0,
            ..perfect()
        };
        let s = score(&bad, &ScoreWeights::DEFAULT);
        assert!((0.0..=1.0).contains(&s.get()));
    }

    #[test]
    fn skor_daima_araliginda() {
        let s = score(&perfect(), &ScoreWeights::DEFAULT);
        assert!((0.0..=1.0).contains(&s.get()));
        assert_eq!(s.percent(), 100);
        assert_eq!(HealthScore::new(-1.0).percent(), 0);
        assert_eq!(HealthScore::new(f64::NAN).get(), 0.0);
    }

    #[test]
    fn erisilebilirlik_en_agir_bilesen() {
        let w = ScoreWeights::DEFAULT;
        for other in [
            w.handshake_success,
            w.http_success,
            w.quic_success,
            w.latency_health,
            w.reset_health,
            w.loss_health,
            w.dns_integrity,
        ] {
            assert!(w.availability > other);
        }
    }

    #[test]
    fn esik_karsilastirmasi() {
        let r = HealthReport::new(perfect(), Classification::Healthy);
        assert!(r.meets(0.82));
        let r = HealthReport::new(ScoreInputs::default(), Classification::Timeout);
        assert!(!r.meets(0.82));
    }
}
