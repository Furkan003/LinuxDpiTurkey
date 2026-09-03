//! Parçalama planı.
//!
//! Bir yerel proxy'nin DPI'a karşı yapabileceği şey sınırlıdır: TCP akışını
//! **ne zaman ve nerede böleceğine** karar verebilir. TTL oyunları veya sahte
//! paketler ham paket erişimi ister; bu motor onları yapamaz ve
//! [`crate::ProxyEngine`] yeteneklerinde bunu dürüstçe bildirir.
//!
//! Plan üretimi saf bir fonksiyondur; yazma işi [`crate::server`] içindedir.

use trdpi_core::profile::FragmentationMode;

use crate::clienthello;

/// Bir yazma işleminin nasıl bölüneceği.
///
/// Dilimler sırayla, aralarında kısa bir bekleme ile gönderilir. Bekleme,
/// parçaların ayrı TCP segmentlerinde gitmesini olası kılar; aksi halde
/// çekirdek onları birleştirebilir.
pub type SplitPlan<'a> = Vec<&'a [u8]>;

/// Verilen veriyi seçilen kipe göre böler.
///
/// Bölünecek bir şey yoksa tek parçalık plan döner — çağıran özel durum
/// yazmak zorunda kalmaz.
pub fn plan<'a>(data: &'a [u8], mode: FragmentationMode) -> SplitPlan<'a> {
    if data.len() < 2 {
        return vec![data];
    }

    let at = match mode {
        FragmentationMode::Off => return vec![data],
        FragmentationMode::Fixed { position } => position as usize,
        FragmentationMode::SniAware => match sni_split_point(data) {
            Some(p) => p,
            // SNI yoksa bu veri muhtemelen ClientHello değil; dokunma.
            None => return vec![data],
        },
    };

    // Bölme noktası veri dışına düşerse bölmek anlamsız.
    if at == 0 || at >= data.len() {
        return vec![data];
    }

    vec![&data[..at], &data[at..]]
}

/// SNI'ın ortasına denk gelen bölme noktası.
///
/// Alan adının tam ortasından bölmek, DPI'ın iki segmenti birleştirmeden
/// eşleştirmesini zorlaştırır. Tek karakterlik isimlerde bölünecek yer yoktur.
pub fn sni_split_point(data: &[u8]) -> Option<usize> {
    let loc = clienthello::find_sni(data)?;
    let len = loc.range.end - loc.range.start;
    if len < 2 {
        return None;
    }
    Some(loc.range.start + len / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn birlestir(plan: &SplitPlan<'_>) -> Vec<u8> {
        plan.iter().flat_map(|s| s.iter().copied()).collect()
    }

    /// En önemli değişmez: parçalama veriyi asla değiştirmez.
    #[test]
    fn parcalar_birlestirilince_orijinal_veri() {
        let data: Vec<u8> = (0..=255u8).collect();
        for mode in [
            FragmentationMode::Off,
            FragmentationMode::Fixed { position: 1 },
            FragmentationMode::Fixed { position: 128 },
            FragmentationMode::Fixed { position: 255 },
            FragmentationMode::SniAware,
        ] {
            let p = plan(&data, mode);
            assert_eq!(birlestir(&p), data, "{mode:?} veriyi bozdu");
        }
    }

    #[test]
    fn kapali_kipte_tek_parca() {
        let data = b"merhaba dunya";
        assert_eq!(plan(data, FragmentationMode::Off).len(), 1);
    }

    #[test]
    fn sabit_konumdan_boluyor() {
        let data = b"0123456789";
        let p = plan(data, FragmentationMode::Fixed { position: 4 });

        assert_eq!(p.len(), 2);
        assert_eq!(p[0], b"0123");
        assert_eq!(p[1], b"456789");
    }

    #[test]
    fn arali_disi_bolme_noktasi_gorulmezden_geliniyor() {
        let data = b"0123456789";
        for position in [0u16, 10, 11, 5000] {
            let p = plan(data, FragmentationMode::Fixed { position });
            assert_eq!(p.len(), 1, "position={position} için bölmemeliydi");
            assert_eq!(birlestir(&p), data);
        }
    }

    #[test]
    fn cok_kisa_veri_bolunmuyor() {
        assert_eq!(plan(b"", FragmentationMode::SniAware).len(), 1);
        assert_eq!(
            plan(b"x", FragmentationMode::Fixed { position: 1 }).len(),
            1
        );
    }

    #[test]
    fn client_hello_olmayan_veri_sni_kipinde_bolunmuyor() {
        let data = b"GET / HTTP/1.1\r\nHost: ornek.test\r\n\r\n";
        let p = plan(data, FragmentationMode::SniAware);
        assert_eq!(p.len(), 1, "ClientHello olmayan veriye dokunulmamalı");
    }

    #[test]
    fn sni_ortasindan_boluyor() {
        let rec = crate::clienthello::tests_support::client_hello("discord.com");
        let loc = clienthello::find_sni(&rec).unwrap();
        let at = sni_split_point(&rec).unwrap();

        assert!(
            at > loc.range.start && at < loc.range.end,
            "bölme noktası SNI'ın içinde değil"
        );

        let p = plan(&rec, FragmentationMode::SniAware);
        assert_eq!(p.len(), 2);
        assert_eq!(birlestir(&p), rec);

        // Hiçbir parça alan adının tamamını içermemeli — bütün amaç bu.
        for parca in &p {
            assert!(
                parca.windows(11).all(|w| w != b"discord.com"),
                "bir parça SNI'ın tamamını taşıyor"
            );
        }
    }

    #[test]
    fn kirpilmis_client_hello_panik_yapmiyor() {
        let rec = crate::clienthello::tests_support::client_hello("discord.com");
        for n in 0..rec.len() {
            let p = plan(&rec[..n], FragmentationMode::SniAware);
            assert_eq!(birlestir(&p), rec[..n]);
        }
    }
}
