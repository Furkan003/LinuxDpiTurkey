//! Tek örnek denetimi.
//!
//! İki kopya aynı anda çalışırsa ikincisi dinleyiciyi açamaz ve koruma
//! sessizce devre dışı kalır. Daha kötüsü: birincisi düzgün kapanmamışsa
//! kimse onu durduramaz, çünkü root'a ait süreci normal kullanıcı
//! öldüremez.
//!
//! Bu yüzden program kendi kopyalarını bulabilir ve durdurabilir.

/// Çalışan başka bir kopyanın kimliği.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// Süreç kimliği.
    pub pid: u32,
    /// Çalıştırılan komut satırı.
    pub cmdline: String,
}

/// `/proc` içindeki bir girdinin **koruma çalıştıran** bir kopyamız olup
/// olmadığını söyler.
///
/// Komut satırı da bakılıyor: durdurma komutu, gözcü süreç ve ölçümler de
/// `trdpi` adını taşıyor. Yalnızca ada bakmak, `--durdur`'un gözcüyü de
/// "kopya" sayıp öldürmesine ve sayının şişmesine yol açıyordu.
///
/// Saf fonksiyon: dosya sistemine dokunmaz, böylece test edilebilir.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn is_own_process(comm: &str, pid: u32, self_pid: u32, cmdline: &str) -> bool {
    pid != self_pid
        && comm.trim() == PROCESS_NAME
        && trdpi_core::paths::is_protection_cmdline(cmdline)
}

/// Sürecin `/proc/<pid>/comm` içindeki adı.
pub use trdpi_core::paths::PROCESS_NAME;

/// Korumanın kimlik dosyasını yazar.
///
/// Yalnızca koruma gerçekten kurulduktan sonra çağrılır. Arayüz bu dosyaya
/// bakarak "koruma çalışıyor mu" sorusunu cevaplar; `--olc` ya da `--geri`
/// gibi geçici çalışmalar dosyaya dokunmadığı için arayüz onları koruma
/// sanmaz.
///
/// Yazılamazsa koruma yine çalışır; yalnızca arayüz durumu `/proc` üzerinden
/// tahmin eder. Bu yüzden hata döndürmüyoruz.
#[cfg(target_os = "linux")]
pub fn write_pidfile() {
    use trdpi_core::paths::{PIDFILE, PIDFILE_FALLBACK};

    let pid = std::process::id().to_string();
    if std::fs::write(PIDFILE, &pid).is_ok() {
        return;
    }
    if let Some(dir) = std::path::Path::new(PIDFILE_FALLBACK).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(PIDFILE_FALLBACK, &pid);
}

/// Kimlik dosyasını siler.
///
/// Yalnızca **kendi** kimliğimizi taşıyorsa silinir: aksi halde araya giren
/// yeni bir kopyanın dosyasını silip arayüzü yanıltırız.
#[cfg(target_os = "linux")]
pub fn clear_pidfile() {
    use trdpi_core::paths::{parse_pid, PIDFILE, PIDFILE_FALLBACK};

    for yol in [PIDFILE, PIDFILE_FALLBACK] {
        let bizim = std::fs::read_to_string(yol)
            .ok()
            .and_then(|c| parse_pid(&c))
            .is_some_and(|p| p == std::process::id());
        if bizim {
            let _ = std::fs::remove_file(yol);
        }
    }
}

/// Linux dışında kimlik dosyası tutulmuyor.
#[cfg(not(target_os = "linux"))]
pub fn write_pidfile() {}

/// Linux dışında kimlik dosyası tutulmuyor.
#[cfg(not(target_os = "linux"))]
pub fn clear_pidfile() {}

/// Kimlik dosyasının işaret ettiği kopya.
///
/// Süreç adına bakan tarama, dosya adı değişirse (elden derlenmiş bir kopya,
/// farklı isimle kurulmuş bir paket) hiçbir şey bulamaz ve kullanıcı
/// korumayı durduramaz. Kimlik dosyası bu bağı koparıyor: koruma kendini
/// yazıyor, durdurma onu okuyor.
#[cfg(target_os = "linux")]
fn from_pidfile(self_pid: u32) -> Option<Instance> {
    use trdpi_core::paths::{parse_pid, PIDFILE, PIDFILE_FALLBACK};

    let icerik = [PIDFILE, PIDFILE_FALLBACK]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())?;
    let pid = parse_pid(&icerik)?;
    if pid == self_pid {
        return None;
    }
    // Süreç gerçekten yaşıyor mu: `kill -9` sonrası dosya kalmış olabilir ve
    // kimlik bu arada başka bir programa verilmiş olabilir.
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).ok()?;
    Some(Instance {
        pid,
        cmdline: cmdline.replace('\0', " ").trim().to_string(),
    })
}

/// Çalışan diğer kopyaları bulur.
///
/// Önce kimlik dosyası, sonra süreç adı taraması. İkisi de gerekli: dosya
/// korumayı kesin olarak bulur, tarama ise dosyasını bırakamadan ölmüş
/// yetim kopyaları yakalar.
#[cfg(target_os = "linux")]
pub fn find_others() -> Vec<Instance> {
    use std::fs;

    let self_pid = std::process::id();
    let mut bulunan = Vec::new();
    if let Some(i) = from_pidfile(self_pid) {
        bulunan.push(i);
    }

    let Ok(entries) = fs::read_dir("/proc") else {
        return bulunan;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let comm = match fs::read_to_string(entry.path().join("comm")) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let cmdline = fs::read_to_string(entry.path().join("cmdline"))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();
        if !is_own_process(&comm, pid, self_pid, &cmdline) {
            continue;
        }
        if bulunan.iter().any(|i: &Instance| i.pid == pid) {
            continue;
        }
        bulunan.push(Instance { pid, cmdline });
    }
    bulunan
}

/// Linux dışında süreç listesi okunmuyor.
#[cfg(not(target_os = "linux"))]
pub fn find_others() -> Vec<Instance> {
    Vec::new()
}

/// Verilen kopyaları nazikçe durdurur, gerekirse zorlar.
///
/// Durdurulan kopya sayısını döner.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn stop_all(instances: &[Instance]) -> usize {
    use std::time::{Duration, Instant};

    let mut durduruldu = 0;
    for inst in instances {
        // SAFETY: kill() yalnızca sinyal gönderir; geçersiz pid için -1 döner.
        unsafe {
            libc::kill(inst.pid as libc::pid_t, libc::SIGINT);
        }
    }

    // Kendi kurallarını geri alabilmeleri için zaman tanı. Geri alma tek bir
    // `nft delete table` ile bir yerel bağlantıdan ibaret; sağlıklı bir kopya
    // bunu yüz milisaniyenin altında bitirir. Tavan yüksek olsun diye
    // beklemek, kullanıcıya doğrudan "durdurmak uzun sürüyor" olarak dönüyor.
    let baslangic = Instant::now();
    while baslangic.elapsed() < Duration::from_millis(1500) {
        if !instances.iter().any(|i| is_alive(i.pid)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    for inst in instances {
        if is_alive(inst.pid) {
            // SAFETY: yukarıdakiyle aynı.
            unsafe {
                libc::kill(inst.pid as libc::pid_t, libc::SIGKILL);
            }
        }
        durduruldu += 1;
    }
    durduruldu
}

/// Linux dışında durdurulacak bir şey yok.
#[cfg(not(target_os = "linux"))]
pub fn stop_all(_instances: &[Instance]) -> usize {
    0
}

/// Sürecin hâlâ yaşayıp yaşamadığı.
#[cfg(target_os = "linux")]
fn is_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn is_alive(_pid: u32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Kendimizi kendi kopyamız sanmamalıyız; sanırsak kendimizi öldürürüz.
    #[test]
    fn kendimizi_kopya_saymiyoruz() {
        assert!(!is_own_process("trdpi\n", 100, 100, "/usr/bin/trdpi"));
    }

    #[test]
    fn ayni_isimli_baska_surec_bulunuyor() {
        assert!(is_own_process("trdpi\n", 101, 100, "/usr/bin/trdpi"));
        assert!(is_own_process("trdpi", 101, 100, "/usr/bin/trdpi"));
    }

    /// Adı bize benzeyen yabancı süreçlere dokunulmamalı.
    #[test]
    fn benzer_isimli_yabanci_surecler_alinmiyor() {
        for yabanci in ["trdpi-dns", "trdpix", "mytrdpi", "sshd", "systemd"] {
            assert!(
                !is_own_process(yabanci, 101, 100, "/usr/bin/trdpi"),
                "{yabanci} bize ait sayıldı"
            );
        }
    }

    #[test]
    fn bos_isim_alinmiyor() {
        assert!(!is_own_process("", 101, 100, "/usr/bin/trdpi"));
        assert!(!is_own_process("   \n", 101, 100, "/usr/bin/trdpi"));
    }

    /// Bu makinede kendimizden başka kopya olmamalı; olsa bile
    /// listeleme panik üretmemeli.
    #[test]
    fn listeleme_panik_yapmiyor() {
        let bulunan = find_others();
        assert!(!bulunan.iter().any(|i| i.pid == std::process::id()));
    }
}

#[cfg(test)]
mod cmdline_testleri {
    use super::*;

    /// Gözcü ve durdurma komutu da `trdpi` adını taşıyor. Bunları kopya
    /// saymak, `--durdur`'un gözcüyü öldürmesine ve sayının şişmesine
    /// ("2 kopya durduruldu") yol açıyordu.
    #[test]
    fn gozcu_ve_durdurma_kopya_sayilmiyor() {
        assert!(!is_own_process(
            "trdpi",
            101,
            100,
            "/usr/bin/trdpi --bekci 42 trdpi_redirect_x"
        ));
        assert!(!is_own_process("trdpi", 101, 100, "/usr/bin/trdpi --geri"));
        assert!(!is_own_process("trdpi", 101, 100, "/usr/bin/trdpi --durdur"));
    }

    #[test]
    fn gercek_koruma_hala_bulunuyor() {
        assert!(is_own_process("trdpi", 101, 100, "/usr/bin/trdpi"));
        assert!(is_own_process("trdpi", 101, 100, "/usr/bin/trdpi --quic-gecir"));
    }
}
