//! Sistem çözümleyicisini yönlendirme ve geri alma.
//!
//! Ubuntu ve türevleri `systemd-resolved` kullanır; `resolvectl` ile arayüz
//! bazında çözümleyici atanabilir ve **standart dışı kapı** da desteklenir —
//! bize gereken tam olarak bu.
//!
//! Değişiklik yapmadan önce mevcut ayar okunur ve geri alma buna göre yapılır.
//! Hiçbir yapılandırma dosyası elle düzenlenmez; sistemin kendi aracı kullanılır.
//!
//! Komut üretimi saf fonksiyondur ve her platformda test edilir; yalnızca
//! çalıştırma Linux'a özeldir.

use std::net::SocketAddr;

/// Sistemin çözümleyiciyi hangi araçla yönettiği.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverManager {
    /// `systemd-resolved` — `resolvectl` ile yönetilir.
    SystemdResolved,
    /// Yönetici tespit edilemedi.
    Unknown,
}

/// Yönlendirme ayarları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverConfig {
    /// Ayarın uygulanacağı ağ arayüzü.
    pub interface: String,
    /// Yönlendirilecek üst çözümleyici.
    pub upstream: SocketAddr,
}

impl ResolverConfig {
    /// Yönlendirmeyi kuran komut.
    ///
    /// `resolvectl` `adres:kapı` biçimini kabul eder; standart dışı kapıya
    /// yönlendirebilmemizin sebebi budur.
    pub fn apply_command(&self) -> Vec<String> {
        argv(&["dns", &self.interface, &format_upstream(self.upstream)])
    }

    /// Önceki ayarı geri getiren komut.
    ///
    /// Boş liste vermek, arayüzü kendi varsayılanına (DHCP'den gelen
    /// çözümleyiciye) döndürür.
    pub fn revert_command(previous: &str, interface: &str) -> Vec<String> {
        let mut cmd = argv(&["dns", interface]);
        for sunucu in previous.split_whitespace() {
            cmd.push(sunucu.to_string());
        }
        cmd
    }

    /// Mevcut ayarı soran komut.
    pub fn query_command(interface: &str) -> Vec<String> {
        argv(&["dns", interface])
    }
}

/// `adres:kapı` biçimi. IPv6 köşeli parantez ister.
fn format_upstream(addr: SocketAddr) -> String {
    match addr {
        SocketAddr::V4(a) => format!("{}:{}", a.ip(), a.port()),
        SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
    }
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_string()).collect()
}

/// Kalıcı ayarın yazıldığı dosya.
///
/// `resolvectl` ile yapılan ayar yalnızca çalışma anındadır ve yeniden
/// başlatınca kaybolur. Kalıcı olması için systemd-resolved'in kendi
/// yapılandırma dizinine bir ek dosya bırakıyoruz. Ana yapılandırma dosyasına
/// dokunmuyoruz; böylece geri alma tek dosyayı silmekten ibaret.
pub const DROPIN_PATH: &str = "/etc/systemd/resolved.conf.d/trdpi.conf";

/// Kalıcı ayar dosyasının içeriği.
pub fn dropin_contents(upstream: SocketAddr) -> String {
    let mut out = String::new();
    out.push_str(
        "# TR-DPI tarafından oluşturuldu.
",
    );
    out.push_str(
        "# Kaldırmak için:  sudo trdpi --geri
",
    );
    out.push_str(
        "[Resolve]
",
    );
    out.push_str(&format!(
        "DNS={}
",
        format_upstream(upstream)
    ));
    out
}

/// Çözümleyici yönetimi hataları.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolverError {
    /// `resolvectl` bulunamadı.
    #[error("systemd-resolved bulunamadı")]
    NotFound,
    /// Yetki reddedildi.
    #[error("çözümleyici ayarını değiştirmek için yetki yok")]
    Denied,
    /// Komut hata döndürdü.
    #[error("çözümleyici ayarlanamadı: {0}")]
    Failed(String),
    /// Ağ arayüzü belirlenemedi.
    #[error("ağ arayüzü bulunamadı")]
    NoInterface,
}

impl ResolverError {
    /// Kullanıcıya gösterilecek metin.
    pub fn user_message(&self) -> &'static str {
        match self {
            Self::NotFound => "Bu sistemde adres çözümleme ayarı otomatik değiştirilemiyor.",
            Self::Denied => "Ayarı değiştirmek için yönetici yetkisi gerekiyor.",
            Self::Failed(_) => "Adres çözümleme ayarı değiştirilemedi.",
            Self::NoInterface => "İnternete çıkan ağ bağlantısı bulunamadı.",
        }
    }
}

#[cfg(target_os = "linux")]
mod exec {
    use super::{ResolverError, ResolverManager};
    use std::process::Command;

    /// `resolvectl` çalıştırır. Kabuk devreye girmez.
    pub fn run(args: &[String]) -> Result<String, ResolverError> {
        let out = Command::new("resolvectl")
            .args(args)
            .output()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ResolverError::NotFound,
                std::io::ErrorKind::PermissionDenied => ResolverError::Denied,
                _ => ResolverError::Failed(e.to_string()),
            })?;

        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }

        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("Access denied") || err.contains("not permitted") {
            return Err(ResolverError::Denied);
        }
        Err(ResolverError::Failed(err.trim().to_owned()))
    }

    /// Kalıcı ayar dosyasını yazar ve servisi yeniden yükler.
    pub fn write_persistent(upstream: std::net::SocketAddr) -> Result<(), ResolverError> {
        use super::{dropin_contents, DROPIN_PATH};

        let path = std::path::Path::new(DROPIN_PATH);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| ResolverError::Failed(format!("dizin oluşturulamadı: {e}")))?;
        }
        std::fs::write(path, dropin_contents(upstream)).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => ResolverError::Denied,
            _ => ResolverError::Failed(e.to_string()),
        })?;
        reload()
    }

    /// Kalıcı ayar dosyasını siler ve servisi yeniden yükler.
    ///
    /// Dosya zaten yoksa bu bir hata değildir; iş bitmiş demektir.
    pub fn remove_persistent() -> Result<(), ResolverError> {
        use super::DROPIN_PATH;

        match std::fs::remove_file(DROPIN_PATH) {
            Ok(()) => reload(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ResolverError::Failed(e.to_string())),
        }
    }

    /// systemd-resolved'i yeniden başlatır.
    fn reload() -> Result<(), ResolverError> {
        let out = Command::new("systemctl")
            .args(["restart", "systemd-resolved"])
            .output()
            .map_err(|e| ResolverError::Failed(e.to_string()))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(ResolverError::Failed(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ))
        }
    }

    /// Sistemin çözümleyiciyi hangi araçla yönettiğini tespit eder.
    pub fn detect_manager() -> ResolverManager {
        match Command::new("resolvectl").arg("--version").output() {
            Ok(o) if o.status.success() => ResolverManager::SystemdResolved,
            _ => ResolverManager::Unknown,
        }
    }

    /// Varsayılan rotayı taşıyan ağ arayüzünün adını bulur.
    ///
    /// Distro adına ya da `eth0` gibi sabit isimlere güvenmiyoruz; çekirdeğin
    /// yönlendirme tablosuna soruyoruz.
    pub fn default_interface() -> Option<String> {
        let out = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        // Biçim: "default via 192.168.1.1 dev enp3s0 proto dhcp ..."
        let mut parts = text.split_whitespace();
        while let Some(p) = parts.next() {
            if p == "dev" {
                return parts.next().map(|s| s.to_string());
            }
        }
        None
    }
}

#[cfg(target_os = "linux")]
pub use exec::{default_interface, detect_manager, remove_persistent, run, write_persistent};

/// Linux dışında çalıştırılacak bir araç yoktur.
#[cfg(not(target_os = "linux"))]
pub fn run(_args: &[String]) -> Result<String, ResolverError> {
    Err(ResolverError::NotFound)
}

/// Linux dışında kalıcı ayar yoktur.
#[cfg(not(target_os = "linux"))]
pub fn write_persistent(_upstream: SocketAddr) -> Result<(), ResolverError> {
    Err(ResolverError::NotFound)
}

/// Linux dışında kalıcı ayar yoktur.
#[cfg(not(target_os = "linux"))]
pub fn remove_persistent() -> Result<(), ResolverError> {
    Ok(())
}

/// Linux dışında bu mekanizma yoktur.
#[cfg(not(target_os = "linux"))]
pub fn detect_manager() -> ResolverManager {
    ResolverManager::Unknown
}

/// Linux dışında ağ arayüzü tespiti yapılmaz.
#[cfg(not(target_os = "linux"))]
pub fn default_interface() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ResolverConfig {
        ResolverConfig {
            interface: "enp3s0".into(),
            upstream: "77.88.8.8:1253".parse().unwrap(),
        }
    }

    /// Asıl mesele bu: kapı numarası komuta girmezse standart dışı kapıya
    /// yönlendirme yapılamaz ve ölçtüğümüz hatta hiçbir şey çalışmaz.
    #[test]
    fn kapi_numarasi_komuta_giriyor() {
        let cmd = config().apply_command();
        assert!(
            cmd.iter().any(|a| a.contains(":1253")),
            "kapı numarası kayboldu: {cmd:?}"
        );
    }

    #[test]
    fn uygulama_komutu_dogru() {
        assert_eq!(
            config().apply_command(),
            vec!["dns", "enp3s0", "77.88.8.8:1253"]
        );
    }

    #[test]
    fn ipv6_koseli_parantezle_yaziliyor() {
        let c = ResolverConfig {
            interface: "enp3s0".into(),
            upstream: "[2a02:6b8::feed:0ff]:1253".parse().unwrap(),
        };
        let cmd = c.apply_command();
        assert!(cmd[2].starts_with('['), "{:?}", cmd);
        assert!(cmd[2].ends_with(":1253"));
    }

    #[test]
    fn geri_alma_onceki_sunuculari_geri_koyuyor() {
        let cmd = ResolverConfig::revert_command("192.168.1.1 192.168.1.2", "enp3s0");
        assert_eq!(cmd, vec!["dns", "enp3s0", "192.168.1.1", "192.168.1.2"]);
    }

    /// Önceki ayar boşsa arayüz kendi varsayılanına döner; bu geçerli bir
    /// geri alma biçimidir.
    #[test]
    fn onceki_ayar_yoksa_varsayilana_donuluyor() {
        let cmd = ResolverConfig::revert_command("", "enp3s0");
        assert_eq!(cmd, vec!["dns", "enp3s0"]);
    }

    #[test]
    fn komutlarda_kabuk_karakteri_yok() {
        let mut hepsi = config().apply_command();
        hepsi.extend(ResolverConfig::revert_command("1.1.1.1", "enp3s0"));
        hepsi.extend(ResolverConfig::query_command("enp3s0"));

        for arg in hepsi {
            for kotu in [';', '|', '&', '`', '\n', '$'] {
                assert!(!arg.contains(kotu), "tehlikeli karakter: {arg}");
            }
        }
    }

    /// Kalıcı dosya, kapı numarasını da taşımalı; taşımazsa yeniden
    /// başlatmadan sonra standart kapıya düşer ve hiçbir şey çalışmaz.
    /// systemd anahtar satirlarini bosluksuz bekler; girintili yazmak
    /// bazi surumlerde ayari sessizce yok sayar.
    #[test]
    fn kalici_dosya_satirlari_girintisiz() {
        let icerik = dropin_contents("77.88.8.8:1253".parse().unwrap());
        for satir in icerik.lines() {
            assert!(
                !satir.starts_with(' ') && !satir.starts_with('\t'),
                "girintili satır: {satir:?}"
            );
        }
    }

    #[test]
    fn kalici_dosya_kapi_numarasini_tasiyor() {
        let icerik = dropin_contents("77.88.8.8:1253".parse().unwrap());
        assert!(icerik.contains("[Resolve]"));
        assert!(icerik.contains("DNS=77.88.8.8:1253"), "{icerik}");
    }

    /// Kullanıcı dosyayı elle bulursa nasıl kaldıracağını görmeli.
    #[test]
    fn kalici_dosya_kendini_aciklıyor() {
        let icerik = dropin_contents("1.1.1.1:53".parse().unwrap());
        assert!(icerik.contains("TR-DPI"));
        assert!(icerik.contains("--geri"));
    }

    #[test]
    fn kalici_dosya_ana_yapilandirmaya_dokunmuyor() {
        assert!(DROPIN_PATH.contains("resolved.conf.d/"), "{DROPIN_PATH}");
        assert!(DROPIN_PATH.ends_with("trdpi.conf"));
    }

    #[test]
    fn her_hatanin_kullanici_metni_var() {
        let hatalar = [
            ResolverError::NotFound,
            ResolverError::Denied,
            ResolverError::Failed("x".into()),
            ResolverError::NoInterface,
        ];
        for h in hatalar {
            let m = h.user_message();
            assert!(!m.is_empty());
            // Kullanıcıya komut ezberletmiyoruz.
            assert!(!m.contains("resolvectl"), "{m}");
        }
    }
}
