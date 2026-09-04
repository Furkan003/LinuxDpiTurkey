//! Kesilen bağlantıyı yeniden deneme.
//!
//! ## Neden bu işe yarıyor
//!
//! Ölçtüğümüz hatta engel, bağlantıların yaklaşık yarısını **rastgele**
//! kesiyor. Başarısızlıklar kümelenmiyor; art arda gelen denemeler birbirinden
//! bağımsız. Ölçüm:
//!
//! ```text
//!                  tek deneme    3 denemede
//! discord.com        %36            %92
//! roblox.com         %48            %92
//! www.roblox.com     %60           %100
//! ```
//!
//! Parçalama ve sahte paket bu hatta hiçbir fark yaratmadı; yeniden deneme
//! yarattı.
//!
//! ## Ne zaman yeniden denemek güvenli
//!
//! Yalnızca **istemciye tek bayt bile gitmeden önce**. Sunucudan yanıt gelip
//! istemciye aktarıldıktan sonra yeniden denemek akışı bozar: istemci
//! yarım bir yanıtın ardından yeni bir oturumun başını görür. Bu modüldeki
//! karar mantığı bu sınırı zorlar.

use std::time::Duration;

/// Yeniden deneme ayarları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// En fazla kaç deneme yapılacağı (ilk deneme dahil).
    pub attempts: u32,
    /// Denemeler arasında beklenecek süre.
    pub delay: Duration,
    /// İlk yanıt baytı için beklenecek süre.
    ///
    /// Bunu aşan bağlantı sessizce ölmüş sayılır ve yeniden denenir.
    pub first_byte_timeout: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            // Ölçüme göre 3 deneme %92'ye çıkarıyor; 4. denemenin katkısı
            // küçük, gecikmesi ise her başarısız bağlantıda hissediliyor.
            attempts: 4,
            delay: Duration::from_millis(120),
            first_byte_timeout: Duration::from_secs(4),
        }
    }
}

/// İlk yazma sonrası sunucudan gelen ilk tepki.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirstResponse {
    /// Veri geldi — bağlantı kurulmuş sayılır.
    Data(Vec<u8>),
    /// Bağlantı sıfırlandı.
    Reset,
    /// Karşı taraf hiçbir şey söylemeden kapattı.
    Closed,
    /// Süre doldu, yanıt gelmedi.
    Timeout,
}

impl FirstResponse {
    /// Bu tepkinin bağlantıyı kurulmuş sayıp saymadığı.
    pub fn is_established(&self) -> bool {
        matches!(self, Self::Data(d) if !d.is_empty())
    }
}

/// Yeniden denemenin gerekip gerekmediği.
///
/// `client_received` istemciye herhangi bir bayt aktarılmış olduğunu belirtir;
/// `true` ise yeniden deneme **hiçbir koşulda** yapılmaz.
pub fn should_retry(
    response: &FirstResponse,
    attempt: u32,
    policy: &RetryPolicy,
    client_received: bool,
) -> bool {
    if client_received {
        return false;
    }
    if response.is_established() {
        return false;
    }
    attempt + 1 < policy.attempts
}

/// Bu denemeden sonra beklenecek süre.
///
/// Kesilme rastgele olduğu için üstel artış gerekmez; uzun bekleme yalnızca
/// kullanıcıyı bekletir.
pub fn delay_for(_attempt: u32, policy: &RetryPolicy) -> Duration {
    policy.delay
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RetryPolicy {
        RetryPolicy {
            attempts: 3,
            delay: Duration::from_millis(10),
            first_byte_timeout: Duration::from_millis(100),
        }
    }

    /// En önemli değişmez: istemciye veri gittiyse yeniden deneme yok.
    /// Aksi halde istemci yarım yanıtın ardından yeni bir oturum görürdü.
    #[test]
    fn istemci_veri_aldiysa_asla_yeniden_denenmiyor() {
        for r in [
            FirstResponse::Reset,
            FirstResponse::Closed,
            FirstResponse::Timeout,
        ] {
            assert!(
                !should_retry(&r, 0, &policy(), true),
                "{r:?} için istemci veri almışken yeniden denendi"
            );
        }
    }

    #[test]
    fn basarili_baglanti_yeniden_denenmiyor() {
        let r = FirstResponse::Data(vec![0x16, 0x03, 0x03]);
        assert!(r.is_established());
        assert!(!should_retry(&r, 0, &policy(), false));
    }

    #[test]
    fn reset_ve_kapanma_yeniden_deneniyor() {
        for r in [
            FirstResponse::Reset,
            FirstResponse::Closed,
            FirstResponse::Timeout,
        ] {
            assert!(should_retry(&r, 0, &policy(), false), "{r:?}");
        }
    }

    #[test]
    fn deneme_hakki_bitince_duruyor() {
        let p = policy();
        assert!(should_retry(&FirstResponse::Reset, 0, &p, false));
        assert!(should_retry(&FirstResponse::Reset, 1, &p, false));
        assert!(
            !should_retry(&FirstResponse::Reset, 2, &p, false),
            "3 deneme hakkı varken 3. denemeden sonra durmalı"
        );
    }

    /// Boş veri "bağlantı kuruldu" sayılmamalı; karşı taraf hiçbir şey
    /// söylemeden kapatmış olabilir.
    #[test]
    fn bos_veri_kurulmus_sayilmiyor() {
        let r = FirstResponse::Data(Vec::new());
        assert!(!r.is_established());
        assert!(should_retry(&r, 0, &policy(), false));
    }

    #[test]
    fn tek_denemelik_ayar_hic_tekrar_etmiyor() {
        let p = RetryPolicy {
            attempts: 1,
            ..policy()
        };
        assert!(!should_retry(&FirstResponse::Reset, 0, &p, false));
    }

    /// Bekleme süresi denemeyle birlikte büyümemeli: kesilme rastgele,
    /// beklemek başarı şansını artırmıyor, yalnızca kullanıcıyı bekletiyor.
    #[test]
    fn bekleme_suresi_sabit() {
        let p = policy();
        assert_eq!(delay_for(0, &p), delay_for(3, &p));
    }

    #[test]
    fn varsayilan_ayar_makul() {
        let p = RetryPolicy::default();
        assert!(p.attempts >= 3, "ölçüm 3 denemede %92 diyor");
        assert!(p.attempts <= 6, "fazla deneme kullanıcıyı bekletir");
        assert!(p.delay <= Duration::from_millis(500));
    }
}
