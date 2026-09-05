//! QUIC engelini aşma.
//!
//! ## Ölçülen engel
//!
//! Bu hatta DPI, QUIC Initial paketini çözüp içindeki sunucu adını okuyor ve
//! engelli ada denk gelince datagramı düşürüyor. Kanıt: **aynı IP'ye aynı
//! porttan** `cloudflare-quic.com` adıyla el sıkışma 0.75 saniyede
//! tamamlanıyor, `discord.com` adıyla zaman aşımına uğruyor. Tek değişken
//! sunucu adı.
//!
//! ## İşe yarayan karşı teknik
//!
//! Gerçek paketten hemen önce, **hedefe ulaşamayacak kadar düşük ömürlü**
//! bozuk bir Initial gönderiyoruz. Denetim ilk gördüğü Initial'a göre karar
//! veriyor; o paket yolda öldüğü için sunucuya varmıyor, gerçek paket ise
//! geçiyor.
//!
//! Ölçüldü (aynı hat, her TTL için üç deneme):
//!
//! | TTL | sonuç |
//! |-----|-------|
//! | 1-2 | başarısız — sahte paket denetimden önce ölüyor |
//! | 3-12 | **18/18 başarılı**, el sıkışma ~0.6 sn |
//!
//! Denetim üç sıçrama uzakta. Varsayılan olarak **iki** sahte paket
//! gönderiyoruz (TTL 4 ve 8): tek bir değer, denetimin daha uzakta olduğu
//! başka bir ağda çalışmayabilir, iki değer aralığı genişletiyor ve maliyeti
//! bağlantı başına tek bir fazladan pakete kalıyor.
//!
//! ## Denenip elenen
//!
//! IP parçalama (`ipfrag`) işe yaramadı: denetim parçaları birleştiriyor.
//! 8 ve 32 baytlık kesimlerle denendi, ikisi de zaman aşımı verdi.

/// Varsayılan sahte paket ömürleri.
pub const DEFAULT_TTLS: [u8; 2] = [4, 8];

/// Bir UDP yükü QUIC Initial paketi mi?
///
/// Uzun başlık biti ve sabit bit açık, tip alanı `00` (Initial) ve sürüm 1.
/// Yalnızca ilk paketler için iş yapıyoruz; kurulmuş bağlantının kısa başlıklı
/// paketlerine dokunmuyoruz.
pub fn is_initial(udp_payload: &[u8]) -> bool {
    udp_payload.len() >= 5
        && (udp_payload[0] & 0xF0) == 0xC0
        && udp_payload[1..5] == [0x00, 0x00, 0x00, 0x01]
}

/// IPv4 başlığının uzunluğu; paket IPv4 değilse `None`.
fn header_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 20 || (buf[0] >> 4) != 4 {
        return None;
    }
    let n = ((buf[0] & 0x0F) as usize) * 4;
    (n >= 20 && buf.len() >= n).then_some(n)
}

/// Paketin IPv4 + UDP olup olmadığını ve UDP yükünün nerede başladığını söyler.
pub fn udp_payload_offset(buf: &[u8]) -> Option<usize> {
    let ip = header_len(buf)?;
    // 17 = UDP
    if buf[9] != 17 {
        return None;
    }
    let bas = ip + 8;
    (buf.len() >= bas).then_some(bas)
}

/// Gerçek Initial paketinden düşük ömürlü, içeriği bozulmuş bir kopya üretir.
///
/// Uzunluk korunuyor: denetimin gördüğü şey aynı boyda bir Initial olsun.
/// Bağlantı kimliği dahil tüm gövde değiştirildiği için sahte paket gerçek bir
/// bağlantı kuramaz; yolda ölmese bile sunucu onu tanımaz ve yok sayar.
pub fn build_fake(real: &[u8], ttl: u8, seed: u64) -> Option<Vec<u8>> {
    let ip = header_len(real)?;
    let total = u16::from_be_bytes([real[2], real[3]]) as usize;
    if total > real.len() || total < ip + 8 + 5 {
        return None;
    }

    let mut p = real[..total].to_vec();
    p[8] = ttl;

    // QUIC yükünün sürüm alanından sonrası: bağlantı kimlikleri, jeton,
    // uzunluk ve şifreli gövde. Hepsi değişiyor.
    let govde = ip + 8 + 5;
    let mut s = seed;
    for b in p[govde..total].iter_mut() {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (s >> 33) as u8;
    }

    // IPv4'te sıfır UDP sağlama toplamı "hesaplanmadı" demektir ve geçerlidir.
    // Bozuk bir toplam göndermektense sıfırlıyoruz.
    p[ip + 6] = 0;
    p[ip + 7] = 0;

    // Yeni bir kimlik: sahte ve gerçek paket aynı IP kimliğini taşımasın.
    let kimlik = (s >> 17) as u16;
    p[4..6].copy_from_slice(&kimlik.to_be_bytes());

    p[10] = 0;
    p[11] = 0;
    let cs = crate::packet::checksum(&p[..ip]);
    p[10..12].copy_from_slice(&cs.to_be_bytes());
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 20 baytlık IPv4 + 8 baytlık UDP başlığı ve verilen yük.
    fn paket(yuk: &[u8]) -> Vec<u8> {
        let toplam = (20 + 8 + yuk.len()) as u16;
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&toplam.to_be_bytes());
        p[8] = 64; // TTL
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&[192, 168, 1, 10]);
        p[16..20].copy_from_slice(&[1, 2, 3, 4]);
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p.extend_from_slice(yuk);
        p
    }

    fn initial_yuk() -> Vec<u8> {
        let mut y = vec![0xC3, 0x00, 0x00, 0x00, 0x01];
        y.extend_from_slice(&[0xAB; 1195]);
        y
    }

    #[test]
    fn initial_taniniyor() {
        assert!(is_initial(&initial_yuk()));
    }

    #[test]
    fn kisa_baslikli_paket_initial_degil() {
        // Kurulmuş bağlantının paketlerine dokunmuyoruz.
        assert!(!is_initial(&[0x40, 0x11, 0x22, 0x33, 0x44]));
    }

    #[test]
    fn handshake_paketi_initial_degil() {
        // Uzun başlık ama tip alanı Handshake (10).
        assert!(!is_initial(&[0xE3, 0x00, 0x00, 0x00, 0x01, 0x00]));
    }

    #[test]
    fn baska_surum_initial_sayilmiyor() {
        assert!(!is_initial(&[0xC3, 0x0A, 0x0A, 0x0A, 0x0A, 0x00]));
    }

    #[test]
    fn cok_kisa_yuk_panik_yapmiyor() {
        assert!(!is_initial(&[]));
        assert!(!is_initial(&[0xC3, 0x00]));
    }

    #[test]
    fn sahte_paket_ttl_ve_uzunlugu_koruyor() {
        let gercek = paket(&initial_yuk());
        let sahte = build_fake(&gercek, 4, 1).expect("sahte kurulamadı");
        assert_eq!(sahte.len(), gercek.len(), "uzunluk değişmemeli");
        assert_eq!(sahte[8], 4, "TTL ayarlanmalı");
    }

    #[test]
    fn sahte_paket_govdeyi_degistiriyor() {
        let gercek = paket(&initial_yuk());
        let sahte = build_fake(&gercek, 4, 1).unwrap();
        // Sürüm alanına kadar aynı, sonrası farklı olmalı.
        assert_eq!(&sahte[28..33], &gercek[28..33], "başlık korunmalı");
        assert_ne!(&sahte[33..], &gercek[33..], "gövde değişmeli");
    }

    #[test]
    fn sahte_paketin_ip_saglamasi_dogru() {
        let gercek = paket(&initial_yuk());
        let sahte = build_fake(&gercek, 4, 7).unwrap();
        assert!(crate::packet::ipv4_checksum_valid(&sahte, 20));
    }

    #[test]
    fn sahte_paket_udp_toplamini_sifirliyor() {
        let gercek = paket(&initial_yuk());
        let sahte = build_fake(&gercek, 4, 7).unwrap();
        assert_eq!(&sahte[26..28], &[0, 0]);
    }

    #[test]
    fn farkli_tohum_farkli_govde() {
        let gercek = paket(&initial_yuk());
        let a = build_fake(&gercek, 4, 1).unwrap();
        let b = build_fake(&gercek, 4, 2).unwrap();
        assert_ne!(a[33..], b[33..]);
    }

    #[test]
    fn ipv4_olmayan_paket_reddediliyor() {
        let mut p = paket(&initial_yuk());
        p[0] = 0x65; // sürüm 6
        assert!(build_fake(&p, 4, 1).is_none());
        assert!(udp_payload_offset(&p).is_none());
    }

    #[test]
    fn udp_olmayan_paket_reddediliyor() {
        let mut p = paket(&initial_yuk());
        p[9] = 6; // TCP
        assert!(udp_payload_offset(&p).is_none());
    }

    #[test]
    fn udp_yuk_baslangici_dogru() {
        let p = paket(&initial_yuk());
        assert_eq!(udp_payload_offset(&p), Some(28));
    }

    #[test]
    fn varsayilan_ttller_olculen_araligin_icinde() {
        // 1 ve 2 ölçüldü ve çalışmadı; 3-12 çalıştı.
        for t in DEFAULT_TTLS {
            assert!((3..=12).contains(&t), "TTL {t} ölçülen aralığın dışında");
        }
    }
}
