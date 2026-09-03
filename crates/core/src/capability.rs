//! Mekanizmalar ve yetenekler.
//!
//! Denetim B1: kaynak belgelerde "backend" kelimesi iki farklı şeyi kastediyordu
//! — bir yerde `windivert | nfqueue | proxy` (paketi nasıl yakaladığımız), başka
//! bir yerde `zapret2 | goodbyedpi | proxy` (hangi motoru kullandığımız). Burada
//! ayrıldılar: **mekanizma** bu modülde, **motor** [`crate::backend::EngineId`].
//!
//! Denetim C5: üç farklı capability struct'ı vardı; tek tanım burada.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Trafiğe müdahale etme yolu. Platformu ima eder ama motoru etmez.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    /// Linux: netfilter kuyruğu üzerinden paket işleme. Ayrıcalık gerektirir.
    Nfqueue,
    /// Windows: WinDivert sürücüsü üzerinden paket işleme. Ayrıcalık gerektirir.
    WinDivert,
    /// Trafiğin yerel bir dinleyiciye yönlendirilmesi. Ayrıcalık gerektirir.
    TransparentProxy,
    /// Yerel SOCKS5/HTTP dinleyici. **Ayrıcalık gerektirmez.**
    LocalProxy,
    /// Hiçbir müdahale yok; yalnızca ölçüm.
    DiagnosticOnly,
}

impl Mechanism {
    /// Tercih sırası — küçük olan önce denenir.
    ///
    /// Kural: en düşük müdahale seviyesi değil, en yüksek kapsama önce gelir;
    /// ancak ayrıcalık gerektirmeyen [`Mechanism::LocalProxy`] daima
    /// ayrıcalıklı olanların ardından, `DiagnosticOnly` en sonda dener.
    pub const PREFERENCE: [Mechanism; 5] = [
        Mechanism::Nfqueue,
        Mechanism::WinDivert,
        Mechanism::TransparentProxy,
        Mechanism::LocalProxy,
        Mechanism::DiagnosticOnly,
    ];

    /// Yükseltilmiş yetki gerektirip gerektirmediği.
    pub fn requires_privilege(self) -> bool {
        !matches!(self, Self::LocalProxy | Self::DiagnosticOnly)
    }

    /// Sistemdeki tüm uygulamaları kapsayıp kapsamadığı.
    ///
    /// [`Mechanism::LocalProxy`] `false` döner: yalnızca proxy'ye yönlendirilmiş
    /// uygulamalar etkilenir. Bu, kullanıcıya dürüstçe söylenmesi gereken bir
    /// kısıttır.
    pub fn is_system_wide(self) -> bool {
        matches!(
            self,
            Self::Nfqueue | Self::WinDivert | Self::TransparentProxy
        )
    }

    /// Sistem objesi (firewall kuralı, route) oluşturup oluşturmadığı.
    ///
    /// `true` dönenler snapshot + rollback zorunludur.
    pub fn mutates_system(self) -> bool {
        matches!(
            self,
            Self::Nfqueue | Self::WinDivert | Self::TransparentProxy
        )
    }
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Nfqueue => "nfqueue",
            Self::WinDivert => "windivert",
            Self::TransparentProxy => "transparent_proxy",
            Self::LocalProxy => "local_proxy",
            Self::DiagnosticOnly => "diagnostic_only",
        })
    }
}

/// Çalışılan sistemde neyin mümkün olduğu.
///
/// Bu yapı **distro adına göre değil, yetenek tespitine göre** doldurulur.
/// `/etc/os-release` yalnızca arayüzde bilgi olarak gösterilir; hiçbir karar
/// ona bakmaz.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Kullanılabilir mekanizmalar.
    pub mechanisms: Vec<Mechanism>,
    /// Yetki yükseltme yolu bulundu mu (polkit/pkexec, UAC).
    pub privilege_escalation: bool,
    /// IPv6 yığını etkin mi.
    pub ipv6: bool,
    /// QUIC/UDP 443 üzerinde işlem yapılabiliyor mu.
    pub quic_handling: bool,
    /// DNS çözümleyicisi uygulama tarafından yönlendirilebiliyor mu.
    pub dns_control: bool,
    /// Sistem bilgisi — yalnızca gösterim içindir, karar girdisi değildir.
    pub system_label: Option<String>,
}

impl Capabilities {
    /// Yalnızca ölçüm yapabilen, hiçbir şeye dokunamayan sistem.
    pub fn diagnostic_only() -> Self {
        Self {
            mechanisms: vec![Mechanism::DiagnosticOnly],
            ..Default::default()
        }
    }

    /// Verilen mekanizmanın kullanılabilir olup olmadığı.
    pub fn supports(&self, mechanism: Mechanism) -> bool {
        self.mechanisms.contains(&mechanism)
    }

    /// Tercih sırasına göre kullanılabilir en iyi mekanizma.
    ///
    /// Yetki yükseltme yoksa ayrıcalık gerektiren mekanizmalar elenir — bu,
    /// polkit reddedildiğinde yerel proxy moduna düşmenin karar noktasıdır.
    pub fn best_mechanism(&self) -> Mechanism {
        Mechanism::PREFERENCE
            .into_iter()
            .find(|m| self.supports(*m) && (self.privilege_escalation || !m.requires_privilege()))
            .unwrap_or(Mechanism::DiagnosticOnly)
    }

    /// Sistem geneli koruma mümkün mü.
    pub fn can_protect_system_wide(&self) -> bool {
        self.best_mechanism().is_system_wide()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> Capabilities {
        Capabilities {
            mechanisms: vec![
                Mechanism::Nfqueue,
                Mechanism::TransparentProxy,
                Mechanism::LocalProxy,
                Mechanism::DiagnosticOnly,
            ],
            privilege_escalation: true,
            ipv6: true,
            quic_handling: true,
            dns_control: true,
            system_label: Some("Linux 6.8".into()),
        }
    }

    #[test]
    fn yetki_varsa_en_kapsamli_mekanizma_secilir() {
        assert_eq!(full().best_mechanism(), Mechanism::Nfqueue);
        assert!(full().can_protect_system_wide());
    }

    /// polkit reddedildiğinde ayrıcalıklı mekanizmalar elenmeli, uygulama
    /// yine de yerel proxy ile çalışabilmeli.
    #[test]
    fn yetki_reddedilirse_yerel_proxya_dusuyor() {
        let caps = Capabilities {
            privilege_escalation: false,
            ..full()
        };
        assert_eq!(caps.best_mechanism(), Mechanism::LocalProxy);
        assert!(!caps.can_protect_system_wide());
    }

    #[test]
    fn hicbir_sey_yoksa_teshis_moduna_dusuyor() {
        assert_eq!(
            Capabilities::default().best_mechanism(),
            Mechanism::DiagnosticOnly
        );
        assert_eq!(
            Capabilities::diagnostic_only().best_mechanism(),
            Mechanism::DiagnosticOnly
        );
    }

    #[test]
    fn ayricaliksiz_mekanizmalar_sistemi_degistirmiyor() {
        for m in Mechanism::PREFERENCE {
            if !m.requires_privilege() {
                assert!(!m.mutates_system(), "{m} yetkisiz sistem değiştiremez");
            }
        }
    }

    #[test]
    fn sistemi_degistiren_her_mekanizma_yetki_istiyor() {
        for m in Mechanism::PREFERENCE {
            if m.mutates_system() {
                assert!(m.requires_privilege(), "{m}");
            }
        }
    }
}
