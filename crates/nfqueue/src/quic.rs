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
//! Gerçek paketten hemen önce, **sunucuya ulaşmayacak** bozuk bir Initial
//! gönderiyoruz. Denetim ilk gördüğü Initial'a göre karar veriyor; o paket
//! sunucuya varmadığı için bağlantıyı bozmuyor, gerçek paket ise geçiyor.
//!
//! Paketin sunucuya varmamasını iki yolla sağlıyoruz — bkz. [`Bozma`].
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

/// Sahte paketin hedefe ulaşmadan ölmesini sağlayan yöntem.
///
/// İkisi de aynı işi yapıyor — denetim paketi görsün, sunucu görmesin — ama
/// farklı zayıflıkları var:
///
/// **Düşük ömür**: denetim gerçek paketi 64 ömürle, bizimkini 4 ile görüyor.
/// Bu tutarsızlık denetlenebilir. Ayrıca denetimin kaç sıçrama uzakta
/// olduğunu bilmek gerekiyor; ağdan ağa değişiyor.
///
/// **Bozuk sağlama toplamı**: denetimler sağlama toplamını genelde
/// doğrulamaz — paketi okur ve kararını ona göre verir. Sunucunun ağ katmanı
/// ise bozuk paketi sessizce atar. Sıçrama sayısından bağımsız çalışır ve
/// ömür tutarsızlığı bırakmaz.
///
/// Hangisinin bu hatta çalıştığını ölçerek seçiyoruz; ikisi birden de
/// gönderilebilir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bozma {
    /// Yalnızca ömrü düşür.
    Omur(u8),
    /// Yalnızca sağlama toplamını boz.
    Toplam,
    /// İkisini birden uygula.
    OmurVeToplam(u8),
    /// Gövdeyi bozmak yerine **geçerli** bir Initial kur.
    ///
    /// İçinde masum bir sunucu adı olan, gerçekten çözülebilir bir paket.
    /// Denetim çözüp meşru bir ad gördüğü için geçiriyor. Gövdesi rastgele
    /// olan sahteyi yok sayan denetimlere karşı bu gerekiyor.
    GecerliInitial(u8),
}

impl Bozma {
    /// Uygulanacak ömür; yoksa paket olduğu gibi kalır.
    fn omur(self) -> Option<u8> {
        match self {
            Bozma::Omur(t) | Bozma::OmurVeToplam(t) | Bozma::GecerliInitial(t) => Some(t),
            Bozma::Toplam => None,
        }
    }

    /// Sağlama toplamı bozulacak mı.
    fn toplam_bozulsun(self) -> bool {
        matches!(self, Bozma::Toplam | Bozma::OmurVeToplam(_))
    }
}

/// Varsayılan sahte paket ömürleri.
pub const DEFAULT_TTLS: [u8; 2] = [4, 8];

/// Varsayılan bozma yöntemleri, gönderilme sırasıyla.
///
/// **Ölçülen sıra bu, tahmin edilen değil.** Bozuk toplamın sıçrama
/// sayısından bağımsız olduğu için daha sağlam olmasını bekliyorduk; bu
/// hatta ölçtük ve **çalışmadı**:
///
/// | yöntem | sonuç |
/// |--------|-------|
/// | bozuk toplam tek başına | zaman aşımı |
/// | düşük ömür (4) | **açık, 0.6 sn** |
/// | aynı pakete ikisi birden | zaman aşımı |
///
/// Yani bu denetim sağlama toplamını doğruluyor ve bozuk paketi yok
/// sayıyor. Aynı pakete ikisini birden uygulamak, denetimin sahteyi hiç
/// görmemesine yol açtığı için çalışan tekniği de öldürüyor.
///
/// Varsayılan olarak **geçerli** Initial gönderiyoruz: gövdesi rastgele olan
/// sahteyi yok sayan bir denetime karşı tek dayanıklı yöntem o. Aynı hatta
/// ölçüldü ve altı denemenin altısı başarılı.
///
/// İki ömür değeri, denetimin farklı uzaklıkta olduğu ağlar için. Bozuk
/// toplam en sonda: burada işe yaramıyor ama toplamı doğrulamayan
/// denetimlerde yarayabilir ve ayrı paket olduğu için zarar vermiyor.
pub fn default_bozmalar() -> Vec<Bozma> {
    vec![
        Bozma::GecerliInitial(DEFAULT_TTLS[0]),
        Bozma::GecerliInitial(DEFAULT_TTLS[1]),
        Bozma::Toplam,
    ]
}

/// Geçerli sahte Initial'da kullanılacak masum sunucu adı.
///
/// Engellenmediği ölçülen, herkesin eriştiği bir ad olmalı.
pub const MASUM_AD: &str = "www.google.com";

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
pub fn build_fake(real: &[u8], bozma: Bozma, seed: u64) -> Option<Vec<u8>> {
    if let Bozma::GecerliInitial(ttl) = bozma {
        return build_valid_fake(real, ttl, MASUM_AD, seed);
    }
    let ip = header_len(real)?;
    let total = u16::from_be_bytes([real[2], real[3]]) as usize;
    if total > real.len() || total < ip + 8 + 5 {
        return None;
    }

    let mut p = real[..total].to_vec();
    if let Some(t) = bozma.omur() {
        p[8] = t;
    }

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

    if bozma.toplam_bozulsun() {
        // Kasten bozuk. Sıfır yazmak olmaz: IPv4'te sıfır "hesaplanmadı"
        // demektir ve sunucu paketi kabul eder. Sıfırdan farklı, yanlış bir
        // değer gerekiyor ki alıcının ağ katmanı atsın.
        let bozuk = ((s >> 5) as u16) | 1;
        p[ip + 6..ip + 8].copy_from_slice(&bozuk.to_be_bytes());
    } else {
        // IPv4'te sıfır "hesaplanmadı" demektir ve geçerlidir; gövdeyi
        // değiştirdiğimiz için eski toplam zaten tutmuyor.
        p[ip + 6] = 0;
        p[ip + 7] = 0;
    }

    // Yeni bir kimlik: sahte ve gerçek paket aynı IP kimliğini taşımasın.
    let kimlik = (s >> 17) as u16;
    p[4..6].copy_from_slice(&kimlik.to_be_bytes());

    p[10] = 0;
    p[11] = 0;
    let cs = crate::packet::checksum(&p[..ip]);
    p[10..12].copy_from_slice(&cs.to_be_bytes());
    Some(p)
}

/// Gerçek paketin adres bilgilerini kullanarak **geçerli** bir Initial kurar.
///
/// Kaynak/hedef adres ve kapılar korunuyor ki denetim aynı akışa ait sansın;
/// yük tamamen yeni ve gerçekten çözülebilir.
fn build_valid_fake(real: &[u8], ttl: u8, sni: &str, seed: u64) -> Option<Vec<u8>> {
    let ip = header_len(real)?;
    if real.len() < ip + 8 || real[9] != 17 {
        return None;
    }

    let yuk = trdpi_core::quic_initial::sahte_initial(sni, seed);
    let toplam = ip + 8 + yuk.len();
    if toplam > u16::MAX as usize {
        return None;
    }

    let mut p = Vec::with_capacity(toplam);
    p.extend_from_slice(&real[..ip + 8]);
    p.extend_from_slice(&yuk);

    p[2..4].copy_from_slice(&(toplam as u16).to_be_bytes());
    p[8] = ttl;
    // Yeni kimlik: sahte ve gerçek paket aynı IP kimliğini taşımasın.
    p[4..6].copy_from_slice(&((seed >> 13) as u16).to_be_bytes());
    // Parçalanmasın diye bayrakları temizliyoruz.
    p[6] = 0;
    p[7] = 0;

    // UDP uzunluğu ve toplamı.
    p[ip + 4..ip + 6].copy_from_slice(&((8 + yuk.len()) as u16).to_be_bytes());
    p[ip + 6] = 0;
    p[ip + 7] = 0;

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
        let sahte = build_fake(&gercek, Bozma::Omur(4), 1).expect("sahte kurulamadı");
        assert_eq!(sahte.len(), gercek.len(), "uzunluk değişmemeli");
        assert_eq!(sahte[8], 4, "TTL ayarlanmalı");
    }

    #[test]
    fn sahte_paket_govdeyi_degistiriyor() {
        let gercek = paket(&initial_yuk());
        let sahte = build_fake(&gercek, Bozma::Omur(4), 1).unwrap();
        // Sürüm alanına kadar aynı, sonrası farklı olmalı.
        assert_eq!(&sahte[28..33], &gercek[28..33], "başlık korunmalı");
        assert_ne!(&sahte[33..], &gercek[33..], "gövde değişmeli");
    }

    #[test]
    fn sahte_paketin_ip_saglamasi_dogru() {
        let gercek = paket(&initial_yuk());
        let sahte = build_fake(&gercek, Bozma::Omur(4), 7).unwrap();
        assert!(crate::packet::ipv4_checksum_valid(&sahte, 20));
    }

    #[test]
    fn sahte_paket_udp_toplamini_sifirliyor() {
        let gercek = paket(&initial_yuk());
        let sahte = build_fake(&gercek, Bozma::Omur(4), 7).unwrap();
        assert_eq!(&sahte[26..28], &[0, 0]);
    }

    #[test]
    fn farkli_tohum_farkli_govde() {
        let gercek = paket(&initial_yuk());
        let a = build_fake(&gercek, Bozma::Omur(4), 1).unwrap();
        let b = build_fake(&gercek, Bozma::Omur(4), 2).unwrap();
        assert_ne!(a[33..], b[33..]);
    }

    #[test]
    fn ipv4_olmayan_paket_reddediliyor() {
        let mut p = paket(&initial_yuk());
        p[0] = 0x65; // sürüm 6
        assert!(build_fake(&p, Bozma::Omur(4), 1).is_none());
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
    fn bozuk_toplam_sifir_olmuyor() {
        // Sıfır toplam "hesaplanmadı" demek ve sunucu paketi kabul eder;
        // o zaman sahte paket gerçek bağlantıyı bozabilir.
        let gercek = paket(&initial_yuk());
        for tohum in 0..200u64 {
            let s = build_fake(&gercek, Bozma::Toplam, tohum).unwrap();
            assert_ne!(&s[26..28], &[0, 0], "tohum {tohum} sıfır toplam üretti");
        }
    }

    #[test]
    fn yalniz_toplam_bozulunca_omur_degismiyor() {
        let gercek = paket(&initial_yuk());
        let s = build_fake(&gercek, Bozma::Toplam, 1).unwrap();
        assert_eq!(s[8], gercek[8], "ömür değişmemeli");
    }

    #[test]
    fn ikisi_birden_uygulanabiliyor() {
        let gercek = paket(&initial_yuk());
        let s = build_fake(&gercek, Bozma::OmurVeToplam(5), 1).unwrap();
        assert_eq!(s[8], 5);
        assert_ne!(&s[26..28], &[0, 0]);
    }

    #[test]
    fn yalniz_omur_bozulunca_toplam_sifirlaniyor() {
        // Gövdeyi değiştirdik; eski toplam zaten tutmuyor. Sıfır geçerli.
        let gercek = paket(&initial_yuk());
        let s = build_fake(&gercek, Bozma::Omur(4), 1).unwrap();
        assert_eq!(&s[26..28], &[0, 0]);
    }

    #[test]
    fn gecerli_initial_adres_bilgisini_koruyor() {
        let gercek = paket(&initial_yuk());
        let s = build_fake(&gercek, Bozma::GecerliInitial(4), 1).unwrap();
        assert_eq!(&s[12..20], &gercek[12..20], "adresler değişmemeli");
        assert_eq!(&s[20..24], &gercek[20..24], "kapılar değişmemeli");
        assert_eq!(s[8], 4, "ömür ayarlanmalı");
    }

    #[test]
    fn gecerli_initial_gercekten_initial() {
        let gercek = paket(&initial_yuk());
        let s = build_fake(&gercek, Bozma::GecerliInitial(4), 1).unwrap();
        let yuk = &s[udp_payload_offset(&s).unwrap()..];
        assert!(is_initial(yuk));
        assert!(yuk.len() >= 1200);
    }

    #[test]
    fn gecerli_initial_uzunluklari_tutarli() {
        let gercek = paket(&initial_yuk());
        let s = build_fake(&gercek, Bozma::GecerliInitial(4), 3).unwrap();
        let toplam = u16::from_be_bytes([s[2], s[3]]) as usize;
        assert_eq!(toplam, s.len(), "IP uzunluğu tutmuyor");
        let udp = u16::from_be_bytes([s[24], s[25]]) as usize;
        assert_eq!(udp, s.len() - 20, "UDP uzunluğu tutmuyor");
        assert!(crate::packet::ipv4_checksum_valid(&s, 20));
    }

    #[test]
    fn varsayilan_gecerli_initial_ile_basliyor() {
        // Gövdesi rastgele olan sahteyi yok sayan denetime karşı tek
        // dayanıklı yöntem bu.
        assert!(matches!(default_bozmalar()[0], Bozma::GecerliInitial(_)));
    }

    #[test]
    fn varsayilanda_iki_farkli_omur_var() {
        // Denetimin uzaklığı ağdan ağa değişiyor.
        let omurler: Vec<_> = default_bozmalar()
            .iter()
            .filter_map(|b| match b {
                Bozma::GecerliInitial(t) => Some(*t),
                _ => None,
            })
            .collect();
        assert_eq!(omurler.len(), 2);
        assert_ne!(omurler[0], omurler[1]);
    }

    #[test]
    fn ayni_pakete_ikisi_birden_varsayilanda_yok() {
        // Ölçüldü: aynı pakete ikisini birden uygulamak çalışanı öldürüyor.
        assert!(!default_bozmalar()
            .iter()
            .any(|b| matches!(b, Bozma::OmurVeToplam(_))));
    }

    #[test]
    fn varsayilan_ttller_olculen_araligin_icinde() {
        // 1 ve 2 ölçüldü ve çalışmadı; 3-12 çalıştı.
        for t in DEFAULT_TTLS {
            assert!((3..=12).contains(&t), "TTL {t} ölçülen aralığın dışında");
        }
    }
}
