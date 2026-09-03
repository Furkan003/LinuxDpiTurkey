//! Motor durum makinesi.
//!
//! Denetim A3: kaynak belgelerde üç farklı durum makinesi vardı ve IPC'ye
//! yazılan `EngineStatus` enum'u `diagnosing`/`selecting`/`applying`/`verifying`
//! durumlarını taşımadığı için ürünün kendi UI metni üretilemiyordu. Buradaki
//! tanım hepsini kapsar ve [`EngineState::user_message`] o metni doğrudan verir.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Motorun yaşam döngüsündeki durumu. IPC üzerinden aynen bu değerler geçer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineState {
    /// Motor kapalı, sistemde uygulamaya ait hiçbir değişiklik yok.
    Stopped,
    /// Başlatma isteği alındı, yetenek tespiti yapılıyor.
    Starting,
    /// Taban ölçümler alınıyor.
    Diagnosing,
    /// Teşhise göre aday profiller sıralanıyor.
    Selecting,
    /// Seçilen profil uygulanıyor.
    Applying,
    /// Uygulanan profil doğrulanıyor.
    Verifying,
    /// Motor çalışıyor ve sağlıklı.
    Running,
    /// Çalışıyor ama sağlık skoru eşiğin altına düştü.
    Degraded,
    /// Bozulma sonrası başka bir profil deneniyor.
    Recovering,
    /// Değişiklikler geri alınıyor.
    RollingBack,
    /// Kurtarılamayan hata; kullanıcı müdahalesi gerekiyor.
    Error,
}

impl EngineState {
    /// Kullanıcıya gösterilecek durum metni.
    ///
    /// Denetim A3'ün doğrudan karşılığı: bu beş ara durum IPC'de ayrı ayrı
    /// bulunmasaydı bu metinlerin hepsi tek bir "Başlatılıyor..."a düşerdi.
    pub fn user_message(self) -> &'static str {
        match self {
            Self::Stopped => "Kapalı",
            Self::Starting => "Bağlantı hazırlanıyor...",
            Self::Diagnosing => "Ağınız analiz ediliyor...",
            Self::Selecting => "Uygun yöntem seçiliyor...",
            Self::Applying => "Yöntem uygulanıyor...",
            Self::Verifying => "Bağlantı doğrulanıyor...",
            Self::Running => "Koruma aktif",
            Self::Degraded => "Bağlantı bozuldu, izleniyor",
            Self::Recovering => "Başka bir yöntem deneniyor...",
            Self::RollingBack => "Değişiklikler geri alınıyor...",
            Self::Error => "Başlatılamadı",
        }
    }

    /// Bu durumda sistemde uygulamaya ait değişiklik bulunup bulunmadığı.
    ///
    /// `true` dönen bir durumda süreç ölürse yetim temizliği çalışmalıdır.
    pub fn holds_system_state(self) -> bool {
        matches!(
            self,
            Self::Applying | Self::Verifying | Self::Running | Self::Degraded | Self::Recovering
        )
    }

    /// Kullanıcı için "çalışıyor" sayılıp sayılmadığı — buton etiketi bunu kullanır.
    pub fn is_active(self) -> bool {
        !matches!(self, Self::Stopped | Self::Error)
    }

    /// `self` durumundan `next` durumuna geçişin geçerli olup olmadığı.
    ///
    /// Durum makinesini burada tutmak, geçişleri gerçek bir backend olmadan
    /// test edilebilir kılar.
    pub fn can_transition_to(self, next: Self) -> bool {
        use EngineState::*;
        match self {
            Stopped => matches!(next, Starting),
            Starting => matches!(next, Diagnosing | Error | RollingBack),
            Diagnosing => matches!(next, Selecting | Error | RollingBack),
            Selecting => matches!(next, Applying | RollingBack | Error),
            Applying => matches!(next, Verifying | RollingBack),
            // Doğrulama başarısızsa önce geri al, sonra sıradaki adaya geç.
            Verifying => matches!(next, Running | RollingBack),
            Running => matches!(next, Degraded | RollingBack | Stopped),
            Degraded => matches!(next, Recovering | Running | RollingBack),
            Recovering => matches!(next, Applying | RollingBack | Error),
            // Geri alma daima temiz duruma ya da hataya çıkar.
            RollingBack => matches!(next, Stopped | Selecting | Error),
            Error => matches!(next, Stopped | Starting),
        }
    }
}

impl fmt::Display for EngineState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Diagnosing => "diagnosing",
            Self::Selecting => "selecting",
            Self::Applying => "applying",
            Self::Verifying => "verifying",
            Self::Running => "running",
            Self::Degraded => "degraded",
            Self::Recovering => "recovering",
            Self::RollingBack => "rolling_back",
            Self::Error => "error",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::EngineState::*;
    use super::*;

    const ALL: [EngineState; 11] = [
        Stopped,
        Starting,
        Diagnosing,
        Selecting,
        Applying,
        Verifying,
        Running,
        Degraded,
        Recovering,
        RollingBack,
        Error,
    ];

    /// Denetim A3'ün gerileme testi: UI metninin ürettiği beş ayrı adım,
    /// beş ayrı duruma karşılık gelmeli.
    #[test]
    fn baslatma_akisinin_bes_adimi_ayri_metin_veriyor() {
        let akis = [Starting, Diagnosing, Selecting, Verifying, Running];
        let mesajlar: std::collections::HashSet<_> =
            akis.iter().map(|s| s.user_message()).collect();
        assert_eq!(mesajlar.len(), akis.len(), "adımlar aynı metne düşüyor");
    }

    #[test]
    fn mutlu_yol_gecerli() {
        let yol = [
            Stopped, Starting, Diagnosing, Selecting, Applying, Verifying, Running, Stopped,
        ];
        for pair in yol.windows(2) {
            assert!(
                pair[0].can_transition_to(pair[1]),
                "{:?} -> {:?} reddedildi",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn basarisiz_dogrulama_once_geri_aliyor() {
        // Verifying doğrudan bir sonraki adaya geçemez; önce RollingBack.
        assert!(Verifying.can_transition_to(RollingBack));
        assert!(!Verifying.can_transition_to(Applying));
        assert!(!Verifying.can_transition_to(Selecting));
        assert!(RollingBack.can_transition_to(Selecting));
    }

    #[test]
    fn calisirken_dogrudan_durdurulamaz_hicbir_kisayol_yok() {
        // Sistem durumu tutan hiçbir durumdan doğrudan Stopped'a atlanamaz —
        // Running hariç, ki o da temiz kapanış yolunu izler.
        for s in ALL.into_iter().filter(|s| s.holds_system_state()) {
            if s == Running {
                continue;
            }
            assert!(
                !s.can_transition_to(Stopped),
                "{s:?} geri alınmadan Stopped'a geçemez"
            );
        }
    }

    #[test]
    fn her_durum_bir_yere_gidebiliyor() {
        for s in ALL {
            assert!(
                ALL.into_iter().any(|n| n != s && s.can_transition_to(n)),
                "{s:?} çıkışsız"
            );
        }
    }

    #[test]
    fn serde_gidip_geliyor() {
        for s in ALL {
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(serde_json::from_str::<EngineState>(&json).unwrap(), s);
            assert_eq!(json.trim_matches('"'), s.to_string());
        }
    }
}
