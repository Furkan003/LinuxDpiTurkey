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

    /// Önbelleği boşaltan komut.
    ///
    /// Çözümleyiciyi değiştirmek önbellekteki eski yanıtları silmiyor:
    /// sansür adresi orada duruyor ve ilk istekler yine oraya gidiyor.
    /// Üstelik sinkhole TCP'yi kabul edip TLS'i kestiği için yedek adres
    /// yolu da devreye girmiyor — bağlantı kurulmuş sayılıyor.
    /// Ölçüldü: temizlemeden ilk tur `000`, ikinci tur `200`.
    pub fn flush_command() -> Vec<String> {
        argv(&["flush-caches"])
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

/// Açılışta ayarı yeniden uygulayan systemd biriminin yolu.
///
/// Neden drop-in dosyası değil: `resolved.conf.d` altındaki `DNS=` satırı
/// **genel** (global) ayarı belirler, systemd-resolved ise sorguları
/// arayüzün kendi çözümleyicisine yönlendirir. DHCP'den çözümleyici alan
/// her bağlantıda — yani neredeyse her ev kullanıcısında — genel ayar hiç
/// devreye girmez. Ölçüldü: drop-in yerindeyken bile `resolvectl query`
/// yanıtı `-- link: enp3s0` diyerek sansür adresini döndürdü.
///
/// Bu birim, çalışırken işe yaradığı doğrulanmış olan **arayüz bazlı**
/// komutun ta kendisini açılışta tekrarlıyor.
pub const UNIT_PATH: &str = "/etc/systemd/system/trdpi-dns.service";

/// Birimin adı.
pub const UNIT_NAME: &str = "trdpi-dns.service";

/// `resolvectl`'in bulunacağı olağan yerler, sırayla.
const RESOLVECTL_ADAYLARI: [&str; 3] = [
    "/usr/bin/resolvectl",
    "/bin/resolvectl",
    "/usr/sbin/resolvectl",
];

/// Birimde yazacak `resolvectl` yolu.
///
/// systemd, yol içermeyen bir `ExecStart`'ı yalnızca sabit bir dizin
/// listesinde arar; dağıtımdan dağıtıma değişebileceği için mutlak yol
/// yazıyoruz. Hiçbiri yoksa en yaygın olanı varsayıyoruz.
pub fn resolvectl_path(var_mi: impl Fn(&str) -> bool) -> &'static str {
    RESOLVECTL_ADAYLARI
        .into_iter()
        .find(|y| var_mi(y))
        .unwrap_or(RESOLVECTL_ADAYLARI[0])
}

/// Açılışta çalışacak birimin içeriği.
pub fn unit_contents(program: &str, interface: &str, upstream: SocketAddr) -> String {
    format!(
        "# TR-DPI tarafından oluşturuldu.
# Kaldırmak için:  sudo trdpi --geri
[Unit]
Description=TR-DPI adres çözümleme ayarı
After=network-online.target systemd-resolved.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={program} dns {interface} {}

[Install]
WantedBy=multi-user.target
",
        format_upstream(upstream)
    )
}

/// Kalıcı ayar dosyasının içeriği.
///
/// Artık yazılmıyor; yalnızca eski kurulumlardan kalan dosyayı tanımak ve
/// silmek için duruyor.
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

    /// Ayarı açılışta tekrarlayan systemd birimini kurar.
    ///
    /// Servis **başlatılmıyor**, yalnızca etkinleştiriliyor: çalışan ayar
    /// `resolvectl` ile zaten uygulandı, birim yalnızca sonraki açılışı
    /// ilgilendiriyor. (systemd-resolved'i yeniden başlatmak birkaç saniye
    /// ad çözümlemesini kesiyor ve o an başlayan indirmeleri çökertiyordu.)
    pub fn write_persistent(
        interface: &str,
        upstream: std::net::SocketAddr,
    ) -> Result<(), ResolverError> {
        use super::{unit_contents, UNIT_NAME, UNIT_PATH};

        let path = std::path::Path::new(UNIT_PATH);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| ResolverError::Failed(format!("dizin oluşturulamadı: {e}")))?;
        }
        let program = super::resolvectl_path(|y| std::path::Path::new(y).exists());
        std::fs::write(path, unit_contents(program, interface, upstream)).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => ResolverError::Denied,
            _ => ResolverError::Failed(e.to_string()),
        })?;

        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", UNIT_NAME])?;
        Ok(())
    }

    /// Kalıcı ayarı kaldırır.
    ///
    /// Zaten yoksa bu bir hata değildir; iş bitmiş demektir. Eski
    /// sürümlerden kalan `resolved.conf.d` dosyası da temizleniyor.
    pub fn remove_persistent() -> Result<(), ResolverError> {
        use super::{DROPIN_PATH, UNIT_NAME, UNIT_PATH};

        let birim_vardi = std::path::Path::new(UNIT_PATH).exists();
        if birim_vardi {
            // Hata yoksayılıyor: birim etkin değilse `disable` yine de
            // başarısız olabilir, ama dosyayı silmemiz gerekiyor.
            let _ = systemctl(&["disable", UNIT_NAME]);
        }

        let mut hata = None;
        for yol in [UNIT_PATH, DROPIN_PATH] {
            match std::fs::remove_file(yol) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => hata = Some(ResolverError::Failed(e.to_string())),
            }
        }
        // `daemon-reload` yok. `disable` bağlantıyı zaten kaldırdı, dosya da
        // silindi; systemd bir sonraki açılışta durumu yeniden okuyor.
        // Yeniden yükleme durdurmayı yarım saniyeden fazla uzatıyordu ve
        // hızlı durdurma bu uygulamada bilerek korunan bir davranış.
        match hata {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// `systemctl` çalıştırır. Kabuk devreye girmez.
    fn systemctl(args: &[&str]) -> Result<(), ResolverError> {
        let out = Command::new("systemctl")
            .args(args)
            .output()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ResolverError::NotFound,
                std::io::ErrorKind::PermissionDenied => ResolverError::Denied,
                _ => ResolverError::Failed(e.to_string()),
            })?;
        if out.status.success() {
            return Ok(());
        }
        Err(ResolverError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        ))
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
pub fn write_persistent(_interface: &str, _upstream: SocketAddr) -> Result<(), ResolverError> {
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

#[cfg(test)]
mod birim_testleri {
    use super::*;

    fn adres(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn birim_arayuz_bazli_komut_yaziyor() {
        // Asıl kusur buydu: genel (global) ayar link ayarı tarafından
        // eziliyordu. Birim, çalışırken işe yaradığı doğrulanan
        // arayüz bazlı komutu tekrarlamalı.
        let m = unit_contents("/usr/bin/resolvectl", "enp3s0", adres("77.88.8.8:1253"));
        assert!(m.contains("ExecStart=/usr/bin/resolvectl dns enp3s0 77.88.8.8:1253"));
    }

    #[test]
    fn birim_ag_hazir_olduktan_sonra_calisiyor() {
        let m = unit_contents("/usr/bin/resolvectl", "wlan0", adres("1.1.1.1:53"));
        assert!(m.contains("After=network-online.target"));
        assert!(m.contains("WantedBy=multi-user.target"));
        assert!(m.contains("Type=oneshot"));
    }

    #[test]
    fn ipv6_koseli_parantezle_yaziliyor() {
        let m = unit_contents("/usr/bin/resolvectl", "eth0", adres("[2606:4700:4700::1111]:53"));
        assert!(m.contains("[2606:4700:4700::1111]:53"), "{m}");
    }

    #[test]
    fn birim_nasil_kaldirilacagini_soyluyor() {
        let m = unit_contents("/usr/bin/resolvectl", "eth0", adres("9.9.9.9:53"));
        assert!(m.contains("trdpi --geri"));
    }
}

#[cfg(test)]
mod yol_testleri {
    use super::*;

    #[test]
    fn bulunan_ilk_yol_seciliyor() {
        assert_eq!(resolvectl_path(|y| y == "/bin/resolvectl"), "/bin/resolvectl");
    }

    #[test]
    fn hicbiri_yoksa_en_yaygini() {
        // Yazarken bulamasak da birim geçerli kalmalı.
        assert_eq!(resolvectl_path(|_| false), "/usr/bin/resolvectl");
    }
}

#[cfg(test)]
mod onbellek_testleri {
    use super::*;

    #[test]
    fn onbellek_temizleme_komutu() {
        assert_eq!(ResolverConfig::flush_command(), vec!["flush-caches"]);
    }
}
