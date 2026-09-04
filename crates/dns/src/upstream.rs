//! Çalışan bir üst çözümleyici bulma.
//!
//! Ölçtüğümüz hatta 53. porttaki dış çözümleyicilerin hepsi kapalı
//! (`connection refused`). Yani "DNS'i 1.1.1.1 yap" tavsiyesi **işe yaramaz**.
//! Çalışan tek yol standart dışı porttan sormak.
//!
//! Bu yüzden adayları sabit sıraya dizmek yerine **denenerek seçiyoruz**:
//! hangisinin yanıt verdiği ağdan ağa değişir ve zamanla da değişebilir.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::wire;

/// Denenecek bir üst çözümleyici.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// Sunucu adresi ve portu.
    pub addr: SocketAddr,
    /// Arayüzde gösterilecek ad.
    pub label: &'static str,
}

/// Aday çözümleyiciler, denenme sırasıyla.
///
/// Standart dışı kapılar önce geliyor: standart kapı engellenen ağlarda tek
/// çalışan seçenek onlar, engellenmeyen ağlarda da sorun çıkarmıyorlar.
pub fn candidates() -> Vec<Upstream> {
    [
        ("77.88.8.8:1253", "Yandex (standart dışı kapı)"),
        ("77.88.8.1:1253", "Yandex yedek (standart dışı kapı)"),
        ("1.1.1.1:53", "Cloudflare"),
        ("8.8.8.8:53", "Google"),
        ("9.9.9.9:53", "Quad9"),
    ]
    .iter()
    .filter_map(|(a, l)| a.parse().ok().map(|addr| Upstream { addr, label: l }))
    .collect()
}

/// Bir adayın denenmesinin sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Yanıt verdi ve yanıt temiz görünüyor.
    Usable {
        /// Yanıt süresi.
        latency: Duration,
    },
    /// Yanıt verdi ama sansür adresi döndürdü — bu çözümleyici de ele geçirilmiş.
    Poisoned,
    /// Hiç yanıt vermedi ya da erişilemedi.
    Unreachable,
}

impl ProbeOutcome {
    /// Bu adayın kullanılabilir olup olmadığı.
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Usable { .. })
    }
}

/// Bir adayı, sonucu bilinen bir alan adıyla dener.
///
/// `canary` engellenmesi beklenen bir alan adı olmalıdır: engellenmemiş bir
/// adla test etmek, ele geçirilmiş bir çözümleyiciyi temiz gösterir.
pub fn probe(up: &Upstream, canary: &str, timeout: Duration) -> ProbeOutcome {
    let started = Instant::now();
    match wire::query(up.addr, canary, timeout) {
        Ok(ans) if wire::is_censorship_response(&ans) => ProbeOutcome::Poisoned,
        Ok(ans) if ans.addresses.is_empty() => ProbeOutcome::Unreachable,
        Ok(_) => ProbeOutcome::Usable {
            latency: started.elapsed(),
        },
        Err(_) => ProbeOutcome::Unreachable,
    }
}

/// Adayları sırayla deneyip ilk çalışanı döner.
///
/// Hiçbiri çalışmıyorsa `None` döner — o durumda DNS'i değiştirmenin faydası
/// yoktur ve kullanıcıya öyle söylenmelidir.
pub fn find_working(canary: &str, timeout: Duration) -> Option<(Upstream, Duration)> {
    for up in candidates() {
        if let ProbeOutcome::Usable { latency } = probe(&up, canary, timeout) {
            return Some((up, latency));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaylar_gecerli_adres_tasiyor() {
        let c = candidates();
        assert!(c.len() >= 3);
        for up in &c {
            assert!(up.addr.port() > 0);
            assert!(!up.label.is_empty());
        }
    }

    /// Standart kapının kapalı olduğu ağlarda tek çalışan seçenek standart dışı
    /// kapılardır; bu yüzden önce denenmeliler.
    #[test]
    fn standart_disi_portlar_once_deneniyor() {
        let c = candidates();
        let ilk_standart = c.iter().position(|u| u.addr.port() == 53);
        let ilk_standart_disi = c.iter().position(|u| u.addr.port() != 53);

        assert!(ilk_standart_disi.is_some(), "standart dışı aday yok");
        if let (Some(s), Some(sd)) = (ilk_standart, ilk_standart_disi) {
            assert!(sd < s, "standart port önce deneniyor");
        }
    }

    #[test]
    fn ayni_adres_iki_kez_denenmiyor() {
        let c = candidates();
        let mut adresler: Vec<_> = c.iter().map(|u| u.addr).collect();
        adresler.sort();
        let onceki = adresler.len();
        adresler.dedup();
        assert_eq!(adresler.len(), onceki, "yinelenen aday var");
    }

    #[test]
    fn kullanilabilirlik_dogru_ayirt_ediliyor() {
        assert!(ProbeOutcome::Usable {
            latency: Duration::from_millis(20)
        }
        .is_usable());
        assert!(!ProbeOutcome::Poisoned.is_usable());
        assert!(!ProbeOutcome::Unreachable.is_usable());
    }

    /// Erişilemeyen bir adres `Unreachable` vermeli, panik değil.
    #[test]
    fn erisilemeyen_aday_panik_yapmiyor() {
        let up = Upstream {
            addr: "127.0.0.1:1".parse().unwrap(),
            label: "test",
        };
        assert_eq!(
            probe(&up, "ornek.test", Duration::from_millis(300)),
            ProbeOutcome::Unreachable
        );
    }
}
