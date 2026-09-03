//! Yetim kural temizliği.
//!
//! Süreç düzgün kapanamazsa (kill -9, elektrik kesintisi) nftables kuralı
//! yerinde kalır. O durumda tüm TCP:443 trafiği artık dinlenmeyen bir porta
//! yönlendirilir ve **internet tamamen kopar.**
//!
//! Bu yüzden uygulama her açılışta kendine ait yetim tabloları arar ve siler.
//! Bu, isteğe bağlı bir özellik değil; tasarımın zorunlu parçasıdır.

use trdpi_core::SessionId;

/// `nft list tables` çıktısından uygulamaya ait tablo adlarını çıkarır.
///
/// Yalnızca `trdpi_` önekli tablolar döner; başka hiçbir uygulamanın tablosu
/// listeye girmez.
pub fn owned_tables(nft_output: &str) -> Vec<String> {
    nft_output
        .lines()
        .filter_map(|line| {
            // Biçim: "table inet trdpi_redirect_a1b2c3d4e5f60000"
            let mut parts = line.split_whitespace();
            if parts.next()? != "table" {
                return None;
            }
            let family = parts.next()?;
            let name = parts.next()?;
            if SessionId::is_owned_by_app(name) {
                Some(format!("{family} {name}"))
            } else {
                None
            }
        })
        .collect()
}

/// Yetim tabloları siler ve silinen tablo adlarını döner.
#[cfg(target_os = "linux")]
pub fn remove_orphans() -> Result<Vec<String>, String> {
    use crate::nft;

    let listing =
        nft::run(&["list".to_string(), "tables".to_string()]).map_err(|e| e.to_string())?;

    let mut silinen = Vec::new();
    for entry in owned_tables(&listing) {
        let mut parts = entry.split_whitespace();
        let (Some(family), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        let cmd: Vec<String> = ["delete", "table", family, name]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if nft::run(&cmd).is_ok() {
            silinen.push(name.to_string());
        }
    }
    Ok(silinen)
}

/// Linux dışında temizlenecek bir şey yoktur.
#[cfg(not(target_os = "linux"))]
pub fn remove_orphans() -> Result<Vec<String>, String> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORNEK: &str = "\
table inet filter
table ip nat
table inet trdpi_redirect_a1b2c3d4e5f60000
table inet firewalld
table ip6 trdpi_redirect_00ff00ff00ff0001
table bridge docker
";

    #[test]
    fn yalnizca_kendi_tablolarimiz_bulunuyor() {
        let bulunan = owned_tables(ORNEK);
        assert_eq!(
            bulunan,
            vec![
                "inet trdpi_redirect_a1b2c3d4e5f60000",
                "ip6 trdpi_redirect_00ff00ff00ff0001"
            ]
        );
    }

    /// En önemli güvenlik değişmezi: başka uygulamaların tablolarına dokunma.
    #[test]
    fn baskasinin_tablosu_asla_listelenmiyor() {
        let bulunan = owned_tables(ORNEK).join(" ");
        for yabanci in ["filter", "nat", "firewalld", "docker"] {
            assert!(
                !bulunan.contains(yabanci),
                "yabancı tablo listelendi: {yabanci}"
            );
        }
    }

    #[test]
    fn bos_ve_bozuk_cikti_sorun_cikarmiyor() {
        assert!(owned_tables("").is_empty());
        assert!(owned_tables("saçma sapan\nveri").is_empty());
        assert!(owned_tables("table").is_empty());
        assert!(owned_tables("table inet").is_empty());
    }

    /// Adı bize benzeyen ama bize ait olmayan tablolar da alınmamalı.
    #[test]
    fn benzer_isimli_yabanci_tablolar_alinmiyor() {
        let girdi = "\
table inet trdpix_something
table inet mytrdpi_redirect_abc
table inet trdpi
";
        assert!(owned_tables(girdi).is_empty());
    }
}
