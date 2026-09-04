//! Yeni sürüm kontrolü.
//!
//! ## Neden kendiliğinden kurmuyor
//!
//! Motor yönetici yetkisiyle çalışıyor. Kendiliğinden güncelleme demek,
//! "internetten inen dosyayı sorgusuz root olarak çalıştır" demek olurdu;
//! araya giren biri makineyi tamamen ele geçirir. Üstelik güncelleme
//! kaynağının kendisi de engellenebilir — sansür aşan bir araçta bu ihtimal
//! varsayılan kabul edilmeli.
//!
//! Bu yüzden burada yapılan tek şey **haber vermek**. Kurulum kullanıcının
//! bir tıkıyla, paket yöneticisi üzerinden olur.
//!
//! Sürüm karşılaştırması saf fonksiyondur ve ağ olmadan test edilir; ağa
//! çıkan tek yer [`check`].

use std::process::{Command, Stdio};
use std::time::Duration;

/// Üç parçalı sürüm numarası.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// Ana sürüm.
    pub major: u32,
    /// Alt sürüm.
    pub minor: u32,
    /// Yama sürümü.
    pub patch: u32,
}

impl Version {
    /// Bu paketin sürümü.
    pub fn current() -> Self {
        parse(env!("CARGO_PKG_VERSION")).unwrap_or(Version {
            major: 0,
            minor: 0,
            patch: 0,
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Bir sürüm dizesini çözer.
///
/// Baştaki `v` ve sondaki ek notlar yok sayılır: `v1.2.3`, `1.2.3-beta`,
/// `1.2.3\n` hepsi kabul edilir.
pub fn parse(raw: &str) -> Option<Version> {
    let s = raw.trim().trim_start_matches(['v', 'V']);
    let core = s.split(['-', '+', ' ']).next()?;

    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    // Eksik parçalar sıfır sayılır: "1.2" geçerli.
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;

    Some(Version {
        major,
        minor,
        patch,
    })
}

/// Kontrolün sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateStatus {
    /// En güncel sürüm kullanılıyor.
    UpToDate,
    /// Daha yeni bir sürüm var.
    Available {
        /// Yayınlanan sürüm.
        version: Version,
    },
    /// Kontrol yapılamadı. Bu bir hata değil; ağ kapalı olabilir.
    Unknown,
}

impl UpdateStatus {
    /// Kullanıcıya gösterilecek metin. Boşsa gösterilecek bir şey yok.
    pub fn message(&self) -> Option<String> {
        match self {
            Self::Available { version } => Some(format!("Yeni sürüm var: {version}")),
            // "Güncelsin" demek için kullanıcıyı rahatsız etmiyoruz.
            Self::UpToDate | Self::Unknown => None,
        }
    }
}

/// İki sürümü karşılaştırıp durumu belirler.
pub fn compare(remote: Version, local: Version) -> UpdateStatus {
    if remote > local {
        UpdateStatus::Available { version: remote }
    } else {
        UpdateStatus::UpToDate
    }
}

/// Sürüm bilgisinin okunacağı adres.
///
/// Depo taşınırsa burası da güncellenmeli. Adres yanlış ya da erişilemez
/// olursa kontrol sessizce [`UpdateStatus::Unknown`] döner; araç çalışmaya
/// devam eder.
pub const VERSION_URL: &str =
    "https://raw.githubusercontent.com/Furkan003/LinuxDpiTurkey/main/SURUM";

/// Yeni sürüm var mı diye bakar.
///
/// Ağ yoksa ya da adrese ulaşılamıyorsa [`UpdateStatus::Unknown`] döner ve
/// kullanıcıya hiçbir şey gösterilmez. Güncelleme kontrolünün başarısız
/// olması, aracın kendi işini yapmasını engellememeli.
pub fn check(url: &str, timeout: Duration) -> UpdateStatus {
    let out = Command::new("curl")
        .args(["-fsS", "--max-time", &timeout.as_secs().to_string(), url])
        .stderr(Stdio::null())
        .output();

    let Ok(out) = out else {
        return UpdateStatus::Unknown;
    };
    if !out.status.success() {
        return UpdateStatus::Unknown;
    }
    let metin = String::from_utf8_lossy(&out.stdout);
    // Uzak dosya bozuksa "güncelsin" demek yanlış olur.
    match parse(&metin) {
        Some(uzak) => compare(uzak, Version::current()),
        None => UpdateStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(major: u32, minor: u32, patch: u32) -> Version {
        Version {
            major,
            minor,
            patch,
        }
    }

    #[test]
    fn surum_cozumleniyor() {
        assert_eq!(parse("1.2.3"), Some(v(1, 2, 3)));
        assert_eq!(parse("v1.2.3"), Some(v(1, 2, 3)));
        assert_eq!(parse("  1.2.3\n"), Some(v(1, 2, 3)));
        assert_eq!(parse("1.2.3-beta"), Some(v(1, 2, 3)));
        assert_eq!(parse("1.2"), Some(v(1, 2, 0)));
        assert_eq!(parse("2"), Some(v(2, 0, 0)));
    }

    #[test]
    fn bozuk_surum_reddediliyor() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("abc"), None);
        assert_eq!(parse("<!DOCTYPE html>"), None);
        assert_eq!(parse("1.x.3"), None);
    }

    #[test]
    fn siralama_dogru() {
        assert!(v(1, 0, 0) < v(1, 0, 1));
        assert!(v(1, 0, 9) < v(1, 1, 0));
        assert!(v(1, 9, 9) < v(2, 0, 0));
        assert!(v(0, 10, 0) > v(0, 9, 9));
    }

    #[test]
    fn yeni_surum_bildiriliyor() {
        let d = compare(v(1, 2, 0), v(1, 1, 0));
        assert_eq!(
            d,
            UpdateStatus::Available {
                version: v(1, 2, 0)
            }
        );
        assert!(d.message().is_some());
    }

    #[test]
    fn ayni_ve_eski_surum_bildirilmiyor() {
        assert_eq!(compare(v(1, 1, 0), v(1, 1, 0)), UpdateStatus::UpToDate);
        assert_eq!(compare(v(1, 0, 0), v(1, 1, 0)), UpdateStatus::UpToDate);
    }

    /// "Güncelsin" bildirimi kullanıcıyı rahatsız etmemeli.
    #[test]
    fn guncel_durumda_mesaj_gosterilmiyor() {
        assert!(UpdateStatus::UpToDate.message().is_none());
        assert!(UpdateStatus::Unknown.message().is_none());
    }

    /// Uzak dosya bozuksa "güncelsin" demek yanlış olur; bilinmiyor demeli.
    #[test]
    fn bozuk_yanit_guncel_sayilmiyor() {
        // parse başarısız olduğunda check() Unknown döner; burada
        // parse'ın kendisinin reddettiğini doğruluyoruz.
        for bozuk in ["<html>", "404: Not Found", ""] {
            assert!(parse(bozuk).is_none(), "{bozuk:?}");
        }
    }

    #[test]
    fn mevcut_surum_okunabiliyor() {
        let s = Version::current();
        assert!(s.major > 0 || s.minor > 0 || s.patch > 0, "sürüm okunamadı");
    }

    /// Ağa erişilemediğinde araç çalışmaya devam etmeli.
    #[test]
    fn erisilemeyen_adres_bilinmiyor_donuyor() {
        let d = check("http://127.0.0.1:1/yok", Duration::from_secs(2));
        assert_eq!(d, UpdateStatus::Unknown);
    }
}
