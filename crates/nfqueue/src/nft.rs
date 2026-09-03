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
    /// Yakalanacak hedef portlar.
    pub ports: Vec<u16>,
}

impl QueueRules {
    /// Oturuma ait varsayılan kural kümesi.
    pub fn new(session: &SessionId, queue_num: u16) -> Self {
        Self {
            table: session.object_name("queue"),
            queue_num,
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

        for port in &self.ports {
            // `bypass`: dinleyen yoksa paket düşmez, geçer.
            cmds.push(argv(&[
                "add",
                "rule",
                "inet",
                t,
                "output",
                "tcp",
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
        QueueRules::new(&SessionId::parse("a1b2c3d4e5f60000").unwrap(), 4200)
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
