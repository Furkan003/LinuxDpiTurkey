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

/// `/proc` içindeki bir girdinin bize ait olup olmadığını söyler.
///
/// Saf fonksiyon: dosya sistemine dokunmaz, böylece test edilebilir.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn is_own_process(comm: &str, pid: u32, self_pid: u32) -> bool {
    pid != self_pid && comm.trim() == PROCESS_NAME
}

/// Sürecin `/proc/<pid>/comm` içindeki adı.
pub const PROCESS_NAME: &str = "trdpi";

/// Çalışan diğer kopyaları bulur.
#[cfg(target_os = "linux")]
pub fn find_others() -> Vec<Instance> {
    use std::fs;

    let self_pid = std::process::id();
    let mut bulunan = Vec::new();

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
        if !is_own_process(&comm, pid, self_pid) {
            continue;
        }
        let cmdline = fs::read_to_string(entry.path().join("cmdline"))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();
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

    // Kendi kurallarını geri alabilmeleri için zaman tanı.
    let baslangic = Instant::now();
    while baslangic.elapsed() < Duration::from_secs(5) {
        if !instances.iter().any(|i| is_alive(i.pid)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
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
        assert!(!is_own_process("trdpi\n", 100, 100));
    }

    #[test]
    fn ayni_isimli_baska_surec_bulunuyor() {
        assert!(is_own_process("trdpi\n", 101, 100));
        assert!(is_own_process("trdpi", 101, 100));
    }

    /// Adı bize benzeyen yabancı süreçlere dokunulmamalı.
    #[test]
    fn benzer_isimli_yabanci_surecler_alinmiyor() {
        for yabanci in ["trdpi-dns", "trdpix", "mytrdpi", "sshd", "systemd"] {
            assert!(
                !is_own_process(yabanci, 101, 100),
                "{yabanci} bize ait sayıldı"
            );
        }
    }

    #[test]
    fn bos_isim_alinmiyor() {
        assert!(!is_own_process("", 101, 100));
        assert!(!is_own_process("   \n", 101, 100));
    }

    /// Bu makinede kendimizden başka kopya olmamalı; olsa bile
    /// listeleme panik üretmemeli.
    #[test]
    fn listeleme_panik_yapmiyor() {
        let bulunan = find_others();
        assert!(!bulunan.iter().any(|i| i.pid == std::process::id()));
    }
}
