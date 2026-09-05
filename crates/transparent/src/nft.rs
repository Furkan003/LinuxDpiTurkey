//! nftables kural yaşam döngüsü.
//!
//! Kurallar `nft` komutuna **argüman dizisi olarak** verilir; hiçbir yerde
//! kabuk (shell) dizesi kurulmaz ve kullanıcı verisi komuta karışmaz. Tablo
//! adı oturum kimliğinden türetilir, böylece yalnızca kendi kurallarımızı
//! sileriz.
//!
//! Komut üretimi saf bir fonksiyondur ve her platformda test edilir; yalnızca
//! çalıştırma Linux'a özeldir.

use std::net::SocketAddr;

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
    /// Muafiyet için kullanılacak paket işareti.
    ///
    /// `Some` ise yalnızca **bizim açtığımız soketler** muaf tutulur; root
    /// olarak çalışan diğer uygulamalar kapsama girer. `None` ise eski
    /// davranışa dönülür ve motorun kullanıcı kimliği muaf tutulur — bu,
    /// root'un tüm trafiğini kapsam dışı bırakır.
    pub exempt_mark: Option<u32>,
    /// Yakalanacak hedef portlar.
    pub ports: Vec<u16>,
    /// QUIC (UDP 443) kapatılsın mı.
    ///
    /// Kapatıldığında uygulamalar anında TCP'ye düşer ve koruma kapsamına
    /// girer. Yalnızca 443 hedeflenir; oyunların gerçek zamanlı trafiği
    /// yüksek portlarda akar ve dokunulmaz.
    pub quic_block: bool,
    /// Adres sorularının çevrileceği sunucu.
    ///
    /// `systemd-resolved` olmayan dağıtımlarda çözümleyiciyi sistemin
    /// aracıyla değiştiremiyoruz. Onun yerine giden adres sorularını doğrudan
    /// çalışan sunucuya çeviriyoruz: hangi çözümleyici ayarlı olursa olsun,
    /// hatta uygulama kendi sunucusunu kullanıyor olsa bile işe yarıyor.
    pub dns_upstream: Option<SocketAddr>,
    /// IPv6 trafiği de yönlendirilsin mi.
    ///
    /// Varsayılan kapalı. Motor açılışta çekirdeğin özgün hedefi IPv6 için
    /// verip vermediğini **sınıyor** ve ancak geçerse burayı açıyor:
    /// yakalayıp taşıyamadığımız trafiği kesmek, korumasız bırakmaktan
    /// çok daha kötü olur.
    pub ipv6: bool,
}

impl RedirectRules {
    /// Oturuma ait varsayılan kural kümesi.
    pub fn new(session: &SessionId, port: u16, engine_uid: u32) -> Self {
        Self {
            table: session.object_name("redirect"),
            port,
            engine_uid,
            exempt_mark: None,
            dns_upstream: None,
            ipv6: false,
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
            self.muafiyet_kurali(t, "output"),
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

        // Aile açıkça belirtiliyor. `inet` ailesindeki kural niteleyicisiz
        // yazılırsa her ikisini de yakalar; IPv6'yı ancak taşıyabildiğimizi
        // sınayarak doğruladığımızda açıyoruz. Yakalayıp taşıyamadığımız
        // trafik tamamen kesilirdi — korumasız bırakmak yeğdir.
        // Adres soruları **her şeyden önce** çevriliyor. Yerel muafiyetten
        // sonra gelirse, çözümleyicisi 127.0.0.53 gibi yerel bir adreste
        // olan sistemlerde kural hiç devreye girmez. `nat` ifadesi
        // sonlandırıcı olduğu için diğer kuralları etkilemiyor.
        let dns = self.dns_commands();
        let bas = if dns.is_empty() { 0 } else { 2 }; // tablo + zincir
        for (i, k) in dns.into_iter().enumerate() {
            cmds.insert(bas + i, k);
        }

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

        if self.ipv6 {
            for port in &self.ports {
                cmds.push(argv(&[
                    "add",
                    "rule",
                    "inet",
                    t,
                    "output",
                    "meta",
                    "nfproto",
                    "ipv6",
                    "tcp",
                    "dport",
                    &port.to_string(),
                    "redirect",
                    "to",
                    &format!(":{}", self.port),
                ]));
            }
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
            self.muafiyet_kurali(t, "quic"),
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

    /// Adres sorularını çalışan sunucuya çeviren kurallar.
    ///
    /// Hedefi zaten o sunucu olan sorular dışarıda bırakılıyor; yoksa
    /// çevrilen paket tekrar kurala düşerdi.
    fn dns_commands(&self) -> Vec<Vec<String>> {
        let Some(up) = self.dns_upstream else {
            return Vec::new();
        };
        // Yalnızca IPv4: çevrilecek sunucularımızın hepsi IPv4.
        let SocketAddr::V4(v4) = up else {
            return Vec::new();
        };
        let ip = v4.ip().to_string();
        let hedef = format!("{}:{}", ip, v4.port());
        let t = &self.table;
        ["udp", "tcp"]
            .iter()
            .map(|proto| {
                argv(&[
                    "add", "rule", "inet", t, "output", "meta", "nfproto", "ipv4", "ip", "daddr",
                    "!=", &ip, proto, "dport", "53", "dnat", "to", &hedef,
                ])
            })
            .collect()
    }

    /// Kendi trafiğimizi muaf tutan kural.
    ///
    /// İşaret kullanılabiliyorsa yalnızca bizim açtığımız soketler muaf
    /// tutulur; kullanılamıyorsa motorun kullanıcı kimliği muaf tutulur ve
    /// root olarak çalışan her şey kapsam dışı kalır.
    fn muafiyet_kurali(&self, table: &str, chain: &str) -> Vec<String> {
        match self.exempt_mark {
            Some(m) => argv(&[
                "add",
                "rule",
                "inet",
                table,
                chain,
                "meta",
                "mark",
                &m.to_string(),
                "return",
            ]),
            None => argv(&[
                "add",
                "rule",
                "inet",
                table,
                chain,
                "meta",
                "skuid",
                &self.engine_uid.to_string(),
                "return",
            ]),
        }
    }

    /// IPv6 sınaması için geçici tablo kuran komutlar.
    ///
    /// Ayrı tabloda duruyor ki sınama bitince tek komutla silinsin ve asıl
    /// kuralların arasına karışmasın. `::1` hedefli, seçilen kapıya giden
    /// bağlantıyı dinleyicimize çeviriyor; motor sonra bağlanıp çekirdeğin
    /// özgün hedefi doğru verip vermediğine bakıyor.
    pub fn selftest_commands(table: &str, listener_port: u16, test_port: u16) -> Vec<Vec<String>> {
        vec![
            argv(&["add", "table", "inet", table]),
            argv(&[
                "add",
                "chain",
                "inet",
                table,
                "output",
                "{ type nat hook output priority -100 ; policy accept ; }",
            ]),
            argv(&[
                "add",
                "rule",
                "inet",
                table,
                "output",
                "ip6",
                "daddr",
                "::1",
                "tcp",
                "dport",
                &test_port.to_string(),
                "redirect",
                "to",
                &format!(":{listener_port}"),
            ]),
        ]
    }

    /// Sınama tablosunu kaldıran komut.
    pub fn selftest_cleanup(table: &str) -> Vec<String> {
        argv(&["delete", "table", "inet", table])
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

#[cfg(test)]
mod ipv6_testleri {
    use super::*;

    fn kurallar() -> RedirectRules {
        let mut r = RedirectRules::new(&SessionId::new(), 9443, 0);
        r.ports = vec![443, 80];
        r
    }

    #[test]
    fn ipv6_varsayilan_olarak_kapali() {
        let cmds = kurallar().install_commands();
        assert!(
            !cmds.iter().any(|c| c.contains(&"ipv6".to_string())),
            "sınanmadan IPv6 kuralı kurulmamalı"
        );
    }

    #[test]
    fn ipv6_acikken_her_kapi_icin_kural_var() {
        let mut r = kurallar();
        r.ipv6 = true;
        let cmds = r.install_commands();
        let v6 = cmds
            .iter()
            .filter(|c| c.contains(&"ipv6".to_string()) && c.contains(&"redirect".to_string()))
            .count();
        assert_eq!(v6, 2, "443 ve 80 için birer IPv6 kuralı bekleniyor");
    }

    #[test]
    fn ipv4_kurallari_ipv6_acikken_de_duruyor() {
        let mut r = kurallar();
        r.ipv6 = true;
        let cmds = r.install_commands();
        let v4 = cmds
            .iter()
            .filter(|c| c.contains(&"ipv4".to_string()) && c.contains(&"redirect".to_string()))
            .count();
        assert_eq!(v4, 2);
    }

    #[test]
    fn sinama_kendi_tablosunda() {
        let cmds = RedirectRules::selftest_commands("trdpi_deneme_x", 9443, 9);
        for c in &cmds {
            assert!(c.contains(&"trdpi_deneme_x".to_string()), "{c:?}");
        }
        assert!(cmds.iter().any(|c| c.contains(&"::1".to_string())));
    }

    #[test]
    fn sinama_tek_komutla_kaldiriliyor() {
        let c = RedirectRules::selftest_cleanup("trdpi_deneme_x");
        assert_eq!(c, vec!["delete", "table", "inet", "trdpi_deneme_x"]);
    }
}

#[cfg(test)]
mod dns_testleri {
    use super::*;

    fn kurallar() -> RedirectRules {
        RedirectRules::new(&SessionId::new(), 9443, 0)
    }

    #[test]
    fn cevirme_kapaliyken_dns_kurali_yok() {
        let cmds = kurallar().install_commands();
        assert!(!cmds.iter().any(|c| c.contains(&"dnat".to_string())));
    }

    #[test]
    fn udp_ve_tcp_icin_birer_kural() {
        let mut r = kurallar();
        r.dns_upstream = Some("77.88.8.8:1253".parse().unwrap());
        let cmds = r.install_commands();
        let dnat: Vec<_> = cmds
            .iter()
            .filter(|c| c.contains(&"dnat".to_string()))
            .collect();
        assert_eq!(dnat.len(), 2, "udp ve tcp için birer kural bekleniyor");
        assert!(dnat.iter().any(|c| c.contains(&"udp".to_string())));
        assert!(dnat.iter().any(|c| c.contains(&"tcp".to_string())));
        assert!(dnat
            .iter()
            .all(|c| c.contains(&"77.88.8.8:1253".to_string())));
    }

    /// Çevrilen paket yeniden kurala düşerse döngü olur.
    #[test]
    fn hedefin_kendisi_disarida_birakiliyor() {
        let mut r = kurallar();
        r.dns_upstream = Some("77.88.8.8:1253".parse().unwrap());
        for c in r
            .install_commands()
            .into_iter()
            .filter(|c| c.contains(&"dnat".to_string()))
        {
            let i = c.iter().position(|x| x == "daddr").expect("daddr yok");
            assert_eq!(c[i + 1], "!=", "hedef dışarıda bırakılmamış: {c:?}");
            assert_eq!(c[i + 2], "77.88.8.8");
        }
    }

    /// Adres soruları muafiyetten **önce** çevrilmeli: motorun kendi
    /// sorularının da doğru yanıt alması gerekiyor.
    #[test]
    fn dns_kurali_muafiyetten_once() {
        let mut r = kurallar();
        r.dns_upstream = Some("77.88.8.8:1253".parse().unwrap());
        let cmds = r.install_commands();
        let dnat = cmds
            .iter()
            .position(|c| c.contains(&"dnat".to_string()))
            .expect("dnat kuralı yok");
        let muafiyet = cmds
            .iter()
            .position(|c| c.contains(&"return".to_string()))
            .expect("muafiyet kuralı yok");
        assert!(dnat < muafiyet, "dns kuralı muafiyetlerden sonra kalmış");
    }

    #[test]
    fn ipv6_sunucu_kabul_edilmiyor() {
        // Çevirdiğimiz sunucuların hepsi IPv4; yanlışlıkla IPv6 verilirse
        // kural üretmiyoruz, sessizce yanlış iş yapmaktansa hiç yapmamak iyi.
        let mut r = kurallar();
        r.dns_upstream = Some("[2001:db8::1]:53".parse().unwrap());
        assert!(!r
            .install_commands()
            .iter()
            .any(|c| c.contains(&"dnat".to_string())));
    }
}
