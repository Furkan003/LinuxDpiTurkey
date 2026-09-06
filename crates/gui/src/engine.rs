//! Motorla konuşma.
//!
//! Arayüz normal kullanıcı olarak çalışır ve **asla root olmaz.** Yetki
//! gerektiren işler `pkexec` ile çalıştırılır; masaüstü kendi parola
//! penceresini gösterir, kullanıcı terminal görmez.
//!
//! Motorun çalışıp çalışmadığını anlamak yetki istemez: kimlik dosyasını ve
//! `/proc` altındaki süreç adlarını okumak herkese açıktır.

use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Motorun bulunduğu yer.
///
/// Önce kurulu konuma, sonra arayüzün yanına bakılır; ikincisi paketlenmeden
/// önce elle denerken işe yarar.
pub fn engine_path() -> PathBuf {
    for aday in ["/usr/bin/trdpi", "/usr/local/bin/trdpi"] {
        let p = PathBuf::from(aday);
        if p.exists() {
            return p;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let yan = dir.join("trdpi");
            if yan.exists() {
                return yan;
            }
        }
    }
    PathBuf::from("trdpi")
}

/// Motorun adı — `/proc/<pid>/comm` bu değeri taşır.
const PROCESS_NAME: &str = "trdpi";

/// Koruma kurulduğunda motorun kimliğini yazdığı dosya.
const PIDFILE: &str = "/run/trdpi.pid";

/// `/run` yazılamayan sistemlerde kullanılan yer.
const PIDFILE_FALLBACK: &str = "/var/lib/trdpi/pid";

/// Kimlik dosyasındaki değerin yaşayan bir motora ait olup olmadığı.
///
/// İki kontrol de gerekli: `kill -9` ile ölen bir motor dosyayı arkasında
/// bırakır ve kimliği bu arada başka bir programa verilmiş olabilir.
#[cfg(target_os = "linux")]
fn pidfile_running() -> Option<bool> {
    let icerik = [PIDFILE, PIDFILE_FALLBACK]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())?;
    let Some(pid) = icerik.trim().parse::<u32>().ok().filter(|p| *p > 1) else {
        return Some(false);
    };
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    Some(comm.trim() == PROCESS_NAME)
}

/// Korumanın şu an çalışıp çalışmadığı.
///
/// Kimlik dosyası varsa **ona** bakılır. Süreç adına bakmak yetmez: durdurma
/// komutunun kendisi de `trdpi` adını taşır, o yüzden ada bakan bir kontrol
/// durdurma sürerken "hâlâ çalışıyor" der ve kullanıcı durduramadığını sanır.
///
/// Dosya hiç yoksa (eski sürüm, yazılamayan dizin) ada bakan eski yönteme
/// düşülür — yanlış "çalışıyor" demek, yanlış "durdu" demekten iyidir.
#[cfg(target_os = "linux")]
pub fn is_running() -> bool {
    if let Some(cevap) = pidfile_running() {
        return cevap;
    }

    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
            .is_none()
        {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
            if comm.trim() == PROCESS_NAME {
                return true;
            }
        }
    }
    false
}

/// Linux dışında motor yok.
#[cfg(not(target_os = "linux"))]
pub fn is_running() -> bool {
    false
}

/// Motoru başlatır.
///
/// `pkexec` masaüstünün parola penceresini açar. Kullanıcı iptal ederse
/// motor başlamaz ve arayüz bunu bir sonraki durum kontrolünde görür.
pub fn start() -> std::io::Result<()> {
    Command::new("pkexec")
        .arg(engine_path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
}

/// Motoru durdurur ve yaptıklarını geri alır.
pub fn stop() -> std::io::Result<()> {
    Command::new("pkexec")
        .arg(engine_path())
        .arg("--geri")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
}

/// `pkexec` kurulu mu.
///
/// Yoksa parola penceresi gösterilemez ve kullanıcıya bunu söylemek gerekir.
pub fn has_pkexec() -> bool {
    Command::new("pkexec")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Motor bulunamasa bile bir yol dönmeli; boş yol çalıştırma hatası verir.
    #[test]
    fn motor_yolu_bos_donmuyor() {
        assert!(!engine_path().as_os_str().is_empty());
    }

    /// Arayüz kendini root sanmamalı.
    #[test]
    fn durum_kontrolu_yetki_istemiyor() {
        // Panik etmeden bir cevap dönmeli; hangi cevap olduğu ortama bağlı.
        let _ = is_running();
    }

    #[test]
    fn surec_adi_motor_ikilisiyle_ayni() {
        assert_eq!(PROCESS_NAME, "trdpi");
    }
}

/// Motorun yazdığı durum dosyasından okunan özet.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Durum {
    /// Kabul edilen bağlantı sayısı.
    pub baglanti: u64,
    /// Kurulan bağlantı sayısı.
    pub kurulan: u64,
    /// Engeli aşılan QUIC bağlantısı sayısı.
    pub quic_asilan: u64,
    /// O an kullanılan teknik.
    pub teknik: String,
    /// Adres çözümlemenin nasıl yapıldığı.
    pub dns: String,
}

/// Motorun anlık durumunu okur; motor çalışmıyorsa `None`.
///
/// Arayüz motorla doğrudan konuşmuyor: motor iki saniyede bir küçük bir
/// dosya yazıyor, biz de onu okuyoruz. Bu yüzden burada ağ ya da süreç
/// erişimi yok, yalnızca bir dosya okuması var.
pub fn durum() -> Option<Durum> {
    use trdpi_core::paths::{status_field, STATUS_FILE};

    let icerik = std::fs::read_to_string(STATUS_FILE).ok()?;
    let sayi = |k: &str| {
        status_field(&icerik, k)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };
    Some(Durum {
        baglanti: sayi("baglanti"),
        kurulan: sayi("kurulan"),
        quic_asilan: sayi("quic_asilan"),
        teknik: status_field(&icerik, "teknik").unwrap_or("-").to_string(),
        dns: status_field(&icerik, "dns").unwrap_or("-").to_string(),
    })
}

/// Açılışta başlatma açık mı?
pub fn acilista_acik() -> bool {
    std::process::Command::new("systemctl")
        .args(["is-enabled", "trdpi.service"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled")
        .unwrap_or(false)
}

/// Açılışta başlatmayı açar ya da kapatır.
///
/// Yetki gerektiği için motorun kendi komutunu `pkexec` ile çağırıyoruz;
/// arayüzün ayrı bir yetki yolu olmasın.
pub fn acilista_ayarla(ac: bool) -> std::io::Result<()> {
    Command::new("pkexec")
        .arg(engine_path())
        .arg(if ac {
            "--acilista-ac"
        } else {
            "--acilista-kapat"
        })
        .status()
        .map(|_| ())
}

/// Bir siteyi ölçer ve motorun çıktısını döner.
///
/// Yönetici yetkisi gerekmiyor: ölçüm sistemi değiştirmiyor, yalnızca
/// soruyor. Bu yüzden `pkexec` yok — kullanıcıya boşuna parola sorulmasın.
pub fn site_dene(site: &str) -> String {
    let cikti = Command::new(engine_path()).arg("--dene").arg(site).output();
    match cikti {
        Ok(o) => {
            let metin = String::from_utf8_lossy(&o.stdout);
            // Terminal biçimini arayüze uyarlıyoruz: başlık satırı düşüyor,
            // girintiler kalkıyor (etiket zaten kendi kenar boşluğunu
            // veriyor) ve komut önerisi düğmeye çevriliyor.
            let satirlar: Vec<String> = metin
                .lines()
                .filter(|l| !l.ends_with("ölçülüyor..."))
                .map(|l| {
                    if l.contains("sudo trdpi") {
                        "BAŞLAT düğmesine basıp tekrar dene.".to_string()
                    } else {
                        l.trim_end().to_string()
                    }
                })
                .skip_while(|l| l.trim().is_empty())
                .collect();
            satirlar.join("
")
        }
        Err(e) => format!("Ölçüm çalıştırılamadı: {e}"),
    }
}

/// Hat raporunu kullanıcının ev dizinine yazar ve yolunu döner.
///
/// Amaç paylaşılabilir bir dosya: başka bir operatördeki biri de çalıştırıp
/// karşılaştırabilsin. Hiçbir yere gönderilmiyor.
pub fn rapor_kaydet() -> std::io::Result<PathBuf> {
    let ev = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let yol = ev.join("trdpi-hat-raporu.txt");
    let cikti = Command::new(engine_path()).arg("--rapor").output()?;
    std::fs::write(&yol, cikti.stdout)?;
    Ok(yol)
}
