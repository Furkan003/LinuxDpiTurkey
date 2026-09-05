//! nftables kural yaşam döngüsü.
//!
//! Kurallar `nft` komutuna **argüman dizisi olarak** verilir; hiçbir yerde
//! kabuk (shell) dizesi kurulmaz ve kullanıcı verisi komuta karışmaz. Tablo
//! adı oturum kimliğinden türetilir, böylece yalnızca kendi kurallarımızı
//! sileriz.
//!
//! Komut üretimi saf bir fonksiyondur ve her platformda test edilir; yalnızca
//! çalıştırma Linux'a özeldir.

use trdpi_core::SessionId;

/// Yönlendirme kurallarının ayarları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectRules {
    /// Bu oturuma ait nftables tablosunun adı.
    pub table: String,
    /// Trafiğin yönlendirileceği yerel port.
    pub port: u16,
    /// Motoru çalıştıran kullanıcının kimliği.
    ///
    /// Bu kullanıcının kendi trafiği yönlendirilmez; aksi halde motorun hedefe
    /// açtığı bağlantı kendine geri döner ve sonsuz döngü oluşur.
    pub engine_uid: u32,
    /// Yakalanacak hedef portlar.
    pub ports: Vec<u16>,
    /// QUIC (UDP 443) kapatılsın mı.
    ///
    /// Kapatıldığında uygulamalar anında TCP'ye düşer ve koruma kapsamına
    /// girer. Yalnızca 443 hedeflenir; oyunların gerçek zamanlı trafiği
    /// yüksek portlarda akar ve dokunulmaz.
    pub quic_block: bool,
}

impl RedirectRules {
    /// Oturuma ait varsayılan kural kümesi.
    pub fn new(session: &SessionId, port: u16, engine_uid: u32) -> Self {
        Self {
            table: session.object_name("redirect"),
            port,
            engine_uid,
            ports: vec![443],
            quic_block: false,
        }
    }

    /// Kuralları kuran `nft` çağrılarını üretir.
    ///
    /// Sıra önemlidir: önce muafiyetler, sonra yönlendirme. nftables kuralları
    /// sırayla değerlendirir ve ilk `return` zinciri terk eder.
    pub fn install_commands(&self) -> Vec<Vec<String>> {
        let t = &self.table;
        let mut cmds = vec![
            argv(&["add", "table", "inet", t]),
            argv(&[
                "add",
                "chain",
                "inet",
                t,
                "output",
                "{ type nat hook output priority -100 ; policy accept ; }",
            ]),
            // Motorun kendi trafiği asla yönlendirilmez — döngü koruması.
            argv(&[
                "add",
                "rule",
                "inet",
                t,
                "output",
                "meta",
                "skuid",
                &self.engine_uid.to_string(),
                "return",
            ]),
            // Yerel trafiğe dokunma.
            argv(&[
                "add",
                "rule",
                "inet",
                t,
                "output",
                "ip",
                "daddr",
                "127.0.0.0/8",
                "return",
            ]),
            argv(&[
                "add", "rule", "inet", t, "output", "ip6", "daddr", "::1", "return",
            ]),
        ];

        // Yalnızca IPv4. `inet` ailesindeki kural niteleyicisiz yazılırsa
        // IPv6'yı da yakalar; oysa dinleyicimiz 127.0.0.1'de ve özgün hedefi
        // yalnızca IPv4 seçeneğiyle (`SOL_IP`) okuyabiliyoruz. Yakalayıp
        // taşıyamadığımız trafik tamamen kesilirdi — dokunmamak yeğdir.
        // IPv6 böylece korumasız ama **çalışır** kalıyor; adres düzeltmesi
        // ona da fayda sağlıyor.
        for port in &self.ports {
            cmds.push(argv(&[
                "add",
                "rule",
                "inet",
                t,
                "output",
                "meta",
                "nfproto",
                "ipv4",
                "tcp",
                "dport",
                &port.to_string(),
                "redirect",
                "to",
                &format!(":{}", self.port),
            ]));
        }

        if self.quic_block {
            cmds.extend(self.quic_commands());
        }

        cmds
    }

    /// QUIC'i kapatan kurallar.
    ///
    /// `reject`, `drop` değil: reddedilen paket uygulamaya **anında** hata
    /// döner ve TCP'ye o saniye düşer. Sessizce düşürseydik uygulama
    /// zaman aşımını beklerdi — kullanıcının gördüğü "yavaşlık" tam olarak
    /// budur.
    ///
    /// Yönlendirme zinciri `nat` tipinde olduğu için reddetme yapamaz;
    /// bu yüzden aynı tabloda ayrı bir `filter` zinciri açılıyor. Tablo
    /// silindiğinde ikisi birden gider.
    fn quic_commands(&self) -> Vec<Vec<String>> {
        let t = &self.table;
        vec![
            argv(&[
                "add",
                "chain",
                "inet",
                t,
                "quic",
                "{ type filter hook output priority 0 ; policy accept ; }",
            ]),
            argv(&[
                "add",
                "rule",
                "inet",
                t,
                "quic",
                "meta",
                "skuid",
                &self.engine_uid.to_string(),
                "return",
            ]),
            argv(&[
                "add",
                "rule",
                "inet",
                t,
                "quic",
                "ip",
                "daddr",
                "127.0.0.0/8",
                "return",
            ]),
            argv(&[
                "add", "rule", "inet", t, "quic", "ip6", "daddr", "::1", "return",
            ]),
            // Yalnızca 443. Oyunların gerçek zamanlı trafiği yüksek
            // portlarda akar ve bu kuralın kapsamına girmez.
            argv(&[
                "add", "rule", "inet", t, "quic", "udp", "dport", "443", "reject",
            ]),
        ]
    }

    /// Kuralları kaldıran `nft` çağrısı.
    ///
    /// Yalnızca kendi tablomuzu siler; başka uygulamaların kurallarına
    /// dokunulmaz.
    pub fn uninstall_command(&self) -> Vec<String> {
        argv(&["delete", "table", "inet", &self.table])
    }

    /// Kuralların yerinde olup olmadığını soran çağrı.
    pub fn verify_command(&self) -> Vec<String> {
        argv(&["list", "table", "inet", &self.table])
    }
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_string()).collect()
}

#[cfg(target_os = "linux")]
mod exec {
    use std::process::Command;

    /// `nft` çalıştırma hataları.
    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    pub enum NftError {
        /// `nft` bulunamadı.
        #[error("nft komutu bulunamadı")]
        NotFound,
        /// Yetki reddedildi.
        #[error("nft için yetki yok")]
        Denied,
        /// `nft` hata döndürdü.
        #[error("nft hatası: {0}")]
        Failed(String),
    }

    /// Tek bir `nft` çağrısını çalıştırır.
    ///
    /// Argümanlar dizi olarak geçirilir; kabuk devreye girmez.
    pub fn run(args: &[String]) -> Result<String, NftError> {
        let out = Command::new("nft")
            .args(args)
            .output()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => NftError::NotFound,
                std::io::ErrorKind::PermissionDenied => NftError::Denied,
                _ => NftError::Failed(e.to_string()),
            })?;

        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }

        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("Operation not permitted") || err.contains("Permission denied") {
            return Err(NftError::Denied);
        }
        Err(NftError::Failed(err.trim().to_owned()))
    }
}

#[cfg(target_os = "linux")]
pub use exec::{run, NftError};

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> RedirectRules {
        RedirectRules::new(&SessionId::parse("a1b2c3d4e5f60000").unwrap(), 9443, 1000)
    }

    #[test]
    fn tablo_adi_nft_icin_gecerli() {
        let r = rules();
        assert!(!r.table.contains('-'));
        assert!(r.table.starts_with("trdpi_"));
        assert!(r
            .table
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_'));
    }

    /// Döngü koruması, yönlendirme kuralından **önce** gelmeli.
    #[test]
    fn kendi_trafigimiz_once_muaf_tutuluyor() {
        let cmds = rules().install_commands();

        let skuid = cmds
            .iter()
            .position(|c| c.contains(&"skuid".to_string()))
            .expect("skuid kuralı yok");
        let redirect = cmds
            .iter()
            .position(|c| c.contains(&"redirect".to_string()))
            .expect("redirect kuralı yok");

        assert!(skuid < redirect, "döngü koruması yönlendirmeden sonra");
    }

    #[test]
    fn yerel_trafik_muaf() {
        let cmds = rules().install_commands();
        let düz: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();

        assert!(düz.iter().any(|c| c.contains("127.0.0.0/8")));
        assert!(düz.iter().any(|c| c.contains("::1")));
    }

    #[test]
    fn silme_yalnizca_kendi_tablosunu_hedefliyor() {
        let r = rules();
        let cmd = r.uninstall_command();

        assert_eq!(cmd, vec!["delete", "table", "inet", &r.table]);
        assert!(!cmd.contains(&"flush".to_string()), "asla flush ruleset");
        assert!(!cmd.contains(&"ruleset".to_string()));
    }

    /// QUIC kapalıyken hiçbir UDP kuralı üretilmemeli.
    #[test]
    fn quic_varsayilan_olarak_kapatilmiyor() {
        let r = rules();
        assert!(!r.quic_block);
        let düz: Vec<String> = r.install_commands().iter().map(|c| c.join(" ")).collect();
        assert!(!düz.iter().any(|c| c.contains("udp")));
    }

    /// Yalnızca 443 reddedilmeli. Oyunların gerçek zamanlı trafiği yüksek
    /// portlarda akar; oraya bir kural sızarsa oyun kopar.
    #[test]
    fn quic_yalnizca_443u_kapatiyor() {
        let mut r = rules();
        r.quic_block = true;
        let udp: Vec<String> = r
            .install_commands()
            .into_iter()
            .map(|c| c.join(" "))
            .filter(|c| c.contains("udp"))
            .collect();

        assert_eq!(udp.len(), 1, "birden fazla UDP kuralı: {udp:?}");
        assert!(udp[0].contains("dport 443"));
        assert!(
            udp[0].contains("reject"),
            "sessiz düşürme uygulamayı bekletir"
        );
    }

    /// Reddetme kuralı, muafiyetlerden **sonra** gelmeli.
    #[test]
    fn quic_muafiyetleri_once_geliyor() {
        let mut r = rules();
        r.quic_block = true;
        let cmds = r.install_commands();

        let zincir = cmds
            .iter()
            .position(|c| c.contains(&"quic".to_string()))
            .expect("quic zinciri yok");
        let skuid = cmds
            .iter()
            .rposition(|c| c.contains(&"skuid".to_string()))
            .unwrap();
        let reddet = cmds
            .iter()
            .position(|c| c.contains(&"reject".to_string()))
            .unwrap();

        assert!(zincir < skuid && skuid < reddet);
    }

    /// QUIC zinciri de aynı tabloda olmalı; tablo silinince ikisi de gitsin.
    #[test]
    fn quic_zinciri_ayni_tabloda() {
        let mut r = rules();
        r.quic_block = true;
        for cmd in r.install_commands() {
            assert!(cmd.contains(&r.table), "yabancı tabloya kural: {cmd:?}");
        }
    }

    #[test]
    fn birden_fazla_port_yakalanabiliyor() {
        let mut r = rules();
        r.ports = vec![443, 80];

        let redirects = r
            .install_commands()
            .into_iter()
            .filter(|c| c.contains(&"redirect".to_string()))
            .count();
        assert_eq!(redirects, 2);
        // IPv6 kapsam dışı: yakalayıp taşıyamadığımız trafiği kesmeyelim.
        for c in r
            .install_commands()
            .into_iter()
            .filter(|c| c.contains(&"redirect".to_string()))
        {
            assert!(
                c.windows(3)
                    .any(|w| w == ["meta".to_string(), "nfproto".to_string(), "ipv4".to_string()]),
                "yönlendirme IPv6'yı da yakalıyor: {c:?}"
            );
        }
    }

    /// Komutlar argüman dizisi olarak çalıştırıldığı için kabuk hiç devreye
    /// girmez; asıl risk **dinamik değerlerin** nft sözdizimine sızmasıdır.
    /// Sabit metinler kod, tablo adı ve portlar veridir — kısıt verinin
    /// üzerinde olmalı.
    #[test]
    fn dinamik_degerler_nft_sozdizimine_sizamiyor() {
        let r = rules();
        let dinamik = [
            r.table.clone(),
            r.port.to_string(),
            r.engine_uid.to_string(),
            r.ports[0].to_string(),
        ];

        for deger in dinamik {
            assert!(
                deger
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "dinamik değer nft sözdizimini bozabilir: {deger}"
            );
        }
    }

    /// Oturum kimliği bozuk olsa bile tablo adı güvenli kalmalı.
    #[test]
    fn bozuk_kimlik_tablo_adina_sizamiyor() {
        for kotu in ["a1b2; nft flush ruleset", "../../x", "a b", "a|b", ""] {
            assert!(SessionId::parse(kotu).is_err(), "reddedilmeliydi: {kotu:?}");
        }
    }

    /// Hiçbir komut toplu silme yapmamalı.
    #[test]
    fn toplu_silme_komutu_uretilmiyor() {
        let r = rules();
        let hepsi: Vec<String> = r
            .install_commands()
            .into_iter()
            .chain([r.uninstall_command(), r.verify_command()])
            .map(|c| c.join(" "))
            .collect();

        for cmd in &hepsi {
            assert!(!cmd.contains("flush"), "toplu temizleme: {cmd}");
            assert!(
                !cmd.contains("ruleset"),
                "tüm kural kümesine dokunuyor: {cmd}"
            );
        }
    }
}
