//! NFQUEUE kural yaşam döngüsü.
//!
//! İki güvenlik detayı burada belirleyicidir:
//!
//! **`bypass`** — kuyruğu dinleyen program yoksa paketler düşürülmez, olduğu
//! gibi geçer. Motor çökerse internet kesilmez; koruma kalkar, o kadar. Şeffaf
//! yönlendirmede bu güvence yoktu.
//!
//! **`meta mark`** — kendi gönderdiğimiz sahte paket de çıkış kancasından
//! geçer. İşaretlenmemiş olsaydı tekrar kuyruğa girer ve sonsuz döngü olurdu.

use trdpi_core::SessionId;

/// Sahte paketlerimize basılan işaret.
///
/// nftables bu işareti taşıyan paketleri kuyruğa almaz.
pub const PACKET_MARK: u32 = 0x54445001;

/// NFQUEUE kurallarının ayarları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueRules {
    /// Bu oturuma ait nftables tablosunun adı.
    pub table: String,
    /// Kuyruk numarası.
    pub queue_num: u16,
    /// QUIC için kuyruğa alınacak UDP kapıları.
    pub udp_ports: Vec<u16>,
    /// TCP kuralları baştan kurulsun mu.
    ///
    /// Varsayılan kapalı: her TCP paketini kullanıcı alanına taşımak boşuna
    /// gecikme demek. Bu teknik yalnızca başka yöntemler yetmediğinde,
    /// çalışma anında açılıyor.
    pub tcp_active: bool,
    /// Yakalanacak hedef portlar.
    pub ports: Vec<u16>,
}

impl QueueRules {
    /// Oturuma ait varsayılan kural kümesi.
    pub fn new(session: &SessionId, queue_num: u16) -> Self {
        Self {
            table: session.object_name("queue"),
            queue_num,
            udp_ports: Vec::new(),
            tcp_active: false,
            ports: vec![443],
        }
    }

    /// Kuralları kuran `nft` çağrılarını üretir.
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
                "{ type filter hook output priority 0 ; policy accept ; }",
            ]),
            // Kendi sahte paketlerimiz kuyruğa girmez — döngü koruması.
            argv(&[
                "add",
                "rule",
                "inet",
                t,
                "output",
                "meta",
                "mark",
                &PACKET_MARK.to_string(),
                "return",
            ]),
        ];

        if self.tcp_active {
            cmds.extend(self.tcp_commands());
        }

        // QUIC. Yalnızca IPv4: sahte paketi ham IPv4 soketinden gönderiyoruz,
        // yakalayıp işleyemediğimiz trafiği kuyruğa almak anlamsız olur.
        for port in &self.udp_ports {
            cmds.push(argv(&[
                "add",
                "rule",
                "inet",
                t,
                "output",
                "meta",
                "nfproto",
                "ipv4",
                "udp",
                "dport",
                &port.to_string(),
                "queue",
                "flags",
                "bypass",
                "to",
                &self.queue_num.to_string(),
            ]));
        }

        cmds
    }

    /// TCP kapıları için kuyruk kuralları.
    ///
    /// Ayrı duruyor çünkü sonradan da eklenebiliyor: bu teknik yalnızca
    /// gerektiğinde açılıyor ve o ana kadar kuyruğa TCP paketi gelmiyor.
    pub fn tcp_commands(&self) -> Vec<Vec<String>> {
        self.ports
            .iter()
            .map(|port| {
                // `bypass`: dinleyen yoksa paket düşmez, geçer.
                argv(&[
                    "add",
                    "rule",
                    "inet",
                    &self.table,
                    "output",
                    "tcp",
                    "dport",
                    &port.to_string(),
                    "queue",
                    "flags",
                    "bypass",
                    "to",
                    &self.queue_num.to_string(),
                ])
            })
            .collect()
    }

    /// Kuralları kaldıran `nft` çağrısı.
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

    /// Tek bir `nft` çağrısını çalıştırır. Kabuk devreye girmez.
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

    fn rules() -> QueueRules {
        let mut r = QueueRules::new(&SessionId::parse("a1b2c3d4e5f60000").unwrap(), 4200);
        // Bu testler kuyruk kuralının biçimine bakıyor; TCP tarafı artık
        // sonradan açıldığı için burada açıkça istiyoruz.
        r.tcp_active = true;
        r
    }

    /// Motor çökerse internet kesilmemeli — `bypass` bunun güvencesi.
    #[test]
    fn kuyruk_kurali_bypass_tasiyor() {
        let cmds = rules().install_commands();
        let kuyruk = cmds
            .iter()
            .find(|c| c.contains(&"queue".to_string()))
            .expect("kuyruk kuralı yok");

        assert!(
            kuyruk.contains(&"bypass".to_string()),
            "bypass yok: motor çökerse tüm trafik düşerdi"
        );
    }

    /// İşaret kontrolü kuyruk kuralından önce gelmeli.
    #[test]
    fn kendi_paketimiz_once_muaf() {
        let cmds = rules().install_commands();
        let mark = cmds
            .iter()
            .position(|c| c.contains(&"mark".to_string()))
            .expect("işaret kuralı yok");
        let queue = cmds
            .iter()
            .position(|c| c.contains(&"queue".to_string()))
            .expect("kuyruk kuralı yok");

        assert!(mark < queue, "döngü koruması kuyruktan sonra kalmış");
    }

    #[test]
    fn tablo_adi_nft_icin_gecerli() {
        let r = rules();
        assert!(!r.table.contains('-'));
        assert!(r
            .table
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_'));
    }

    #[test]
    fn silme_yalnizca_kendi_tablosunu_hedefliyor() {
        let r = rules();
        assert_eq!(
            r.uninstall_command(),
            vec!["delete", "table", "inet", &r.table]
        );
    }

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
            assert!(!cmd.contains("flush"), "{cmd}");
            assert!(!cmd.contains("ruleset"), "{cmd}");
        }
    }

    #[test]
    fn dinamik_degerler_guvenli() {
        let r = rules();
        for deger in [
            r.table.clone(),
            r.queue_num.to_string(),
            r.ports[0].to_string(),
        ] {
            assert!(deger
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        }
    }
}

#[cfg(test)]
mod tcp_testleri {
    use super::*;

    fn kurallar() -> QueueRules {
        let mut r = QueueRules::new(&SessionId::new(), 4200);
        r.ports = vec![443];
        r.udp_ports = vec![443];
        r
    }

    #[test]
    fn tcp_varsayilan_olarak_kuyruga_alinmiyor() {
        // Her TCP paketini kullanıcı alanına taşımak boşuna gecikme.
        let cmds = kurallar().install_commands();
        assert!(!cmds
            .iter()
            .any(|c| c.contains(&"tcp".to_string()) && c.contains(&"queue".to_string())));
    }

    #[test]
    fn udp_kurali_yine_de_kuruluyor() {
        let cmds = kurallar().install_commands();
        assert!(cmds
            .iter()
            .any(|c| c.contains(&"udp".to_string()) && c.contains(&"queue".to_string())));
    }

    #[test]
    fn acilinca_tcp_kurali_uretiliyor() {
        let mut r = kurallar();
        r.tcp_active = true;
        let cmds = r.install_commands();
        assert!(cmds
            .iter()
            .any(|c| c.contains(&"tcp".to_string()) && c.contains(&"queue".to_string())));
    }

    #[test]
    fn sonradan_eklenen_kural_ayni_tabloda() {
        let r = kurallar();
        for c in r.tcp_commands() {
            assert!(c.contains(&r.table), "yabancı tabloya kural: {c:?}");
            assert!(c.contains(&"bypass".to_string()), "bypass yok: {c:?}");
        }
    }
}
