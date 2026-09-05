//! Geçerli bir QUIC Initial paketi kurar.
//!
//! ## Neden gerekiyor
//!
//! Şimdiye kadar gönderdiğimiz sahte Initial'ın gövdesi rastgeleydi:
//! denetim onu çözemiyordu. Ölçtüğümüz hatta bu yetti — denetim çözemediğine
//! bakmadan karar veriyor. Ama "çözemediğim Initial'a karar vermem" diyen bir
//! denetim tekniği anında öldürür.
//!
//! Bu modül **gerçekten geçerli** bir Initial üretiyor: denetim çözüyor,
//! içinde masum bir sunucu adı görüyor ve geçiriyor. Sunucuya varmaması yine
//! düşük ömürle sağlanıyor; varsa bile bağlantı kimliği uydurma olduğu için
//! sunucu onu tanımaz.
//!
//! ## Yapı (RFC 9000 §17.2.2, RFC 9001 §5.2)
//!
//! ```text
//! uzun başlık | sürüm | DCID | SCID | jeton | uzunluk | paket no
//!                                                       └─ şifreli: CRYPTO(ClientHello) + dolgu
//! ```
//!
//! Anahtarlar bağlantı kimliğinden (DCID) türüyor ve kimlik açıkta gidiyor;
//! yani denetim de aynı anahtarı türetip çözebiliyor. Sır saklamıyoruz.

use crate::kripto::{aes128_gcm_sifrele, hkdf_expand_label, hkdf_extract, Aes128};

/// QUIC v1 başlangıç tuzu (RFC 9001 §5.2).
const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Datagramın en az bu kadar olması gerekiyor (RFC 9000 §14.1).
const EN_AZ_DATAGRAM: usize = 1200;

/// İstemci tarafı Initial anahtarları.
#[derive(Debug, PartialEq, Eq)]
pub struct Anahtarlar {
    /// Yük şifreleme anahtarı.
    pub key: [u8; 16],
    /// Nonce türetmede kullanılan taban.
    pub iv: [u8; 12],
    /// Başlık koruma anahtarı.
    pub hp: [u8; 16],
}

/// Bağlantı kimliğinden istemci Initial anahtarlarını türetir.
pub fn anahtarlar(dcid: &[u8]) -> Anahtarlar {
    let initial = hkdf_extract(&INITIAL_SALT, dcid);
    let istemci = hkdf_expand_label(&initial, "client in", 32);
    let key = hkdf_expand_label(&istemci, "quic key", 16);
    let iv = hkdf_expand_label(&istemci, "quic iv", 12);
    let hp = hkdf_expand_label(&istemci, "quic hp", 16);
    Anahtarlar {
        key: key.try_into().expect("16 bayt"),
        iv: iv.try_into().expect("12 bayt"),
        hp: hp.try_into().expect("16 bayt"),
    }
}

/// QUIC değişken uzunluklu tamsayı kodlaması.
fn varint(deger: u64, out: &mut Vec<u8>) {
    match deger {
        0..=63 => out.push(deger as u8),
        64..=16383 => out.extend_from_slice(&((deger as u16) | 0x4000).to_be_bytes()),
        16384..=1_073_741_823 => out.extend_from_slice(&((deger as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(deger | 0xC000_0000_0000_0000).to_be_bytes()),
    }
}

/// Verilen sunucu adıyla bir TLS ClientHello kurar.
///
/// Yalnızca denetimin okuyacağı kadarını doğru kuruyoruz: sürüm, rastgelelik,
/// şifre takımları ve sunucu adı uzantısı. Gerçek bir el sıkışma kurmayacak.
pub fn client_hello(sni: &str, tohum: u64) -> Vec<u8> {
    let mut rastgele = [0u8; 32];
    let mut s = tohum;
    for b in rastgele.iter_mut() {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (s >> 33) as u8;
    }

    // --- uzantılar ---
    let mut uzantilar = Vec::new();

    // server_name (0x0000)
    let ad = sni.as_bytes();
    let mut sunucu_adi = Vec::new();
    sunucu_adi.extend_from_slice(&((ad.len() + 3) as u16).to_be_bytes()); // liste uzunluğu
    sunucu_adi.push(0); // tür: host_name
    sunucu_adi.extend_from_slice(&(ad.len() as u16).to_be_bytes());
    sunucu_adi.extend_from_slice(ad);
    uzantilar.extend_from_slice(&0u16.to_be_bytes());
    uzantilar.extend_from_slice(&(sunucu_adi.len() as u16).to_be_bytes());
    uzantilar.extend_from_slice(&sunucu_adi);

    // supported_versions (0x002b): yalnızca TLS 1.3
    uzantilar.extend_from_slice(&0x002bu16.to_be_bytes());
    uzantilar.extend_from_slice(&3u16.to_be_bytes());
    uzantilar.extend_from_slice(&[0x02, 0x03, 0x04]);

    // supported_groups (0x000a): x25519
    uzantilar.extend_from_slice(&0x000au16.to_be_bytes());
    uzantilar.extend_from_slice(&4u16.to_be_bytes());
    uzantilar.extend_from_slice(&[0x00, 0x02, 0x00, 0x1d]);

    // quic_transport_parameters (0x0039): boş ama var olması gerekiyor
    uzantilar.extend_from_slice(&0x0039u16.to_be_bytes());
    uzantilar.extend_from_slice(&0u16.to_be_bytes());

    // --- gövde ---
    let mut govde = Vec::new();
    govde.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
    govde.extend_from_slice(&rastgele);
    govde.push(0); // boş oturum kimliği
    govde.extend_from_slice(&4u16.to_be_bytes()); // şifre takımı listesi
    govde.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]); // TLS_AES_128_GCM_SHA256, 256
    govde.extend_from_slice(&[0x01, 0x00]); // sıkıştırma yok
    govde.extend_from_slice(&(uzantilar.len() as u16).to_be_bytes());
    govde.extend_from_slice(&uzantilar);

    // --- el sıkışma başlığı ---
    let mut ch = Vec::with_capacity(4 + govde.len());
    ch.push(0x01); // ClientHello
    let u = govde.len();
    ch.extend_from_slice(&[(u >> 16) as u8, (u >> 8) as u8, u as u8]);
    ch.extend_from_slice(&govde);
    ch
}

/// Verilen sunucu adıyla geçerli, şifrelenmiş bir Initial datagramı üretir.
///
/// Dönen şey UDP yükü: doğrudan gönderilecek QUIC paketi.
pub fn sahte_initial(sni: &str, tohum: u64) -> Vec<u8> {
    let mut s = tohum;
    let mut sonraki = || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (s >> 33) as u8
    };
    let dcid: Vec<u8> = (0..8).map(|_| sonraki()).collect();
    let scid: Vec<u8> = (0..8).map(|_| sonraki()).collect();

    let a = anahtarlar(&dcid);
    let ch = client_hello(sni, tohum);

    // CRYPTO çerçevesi: tür 0x06, uzaklık 0, uzunluk, veri.
    let mut cerceve = vec![0x06];
    varint(0, &mut cerceve);
    varint(ch.len() as u64, &mut cerceve);
    cerceve.extend_from_slice(&ch);

    // Başlığın uzunluk alanı dışındaki kısmı.
    const PN_UZUNLUK: usize = 4;
    let mut bas = Vec::new();
    bas.push(0xC3); // uzun başlık + sabit bit + Initial + 4 baytlık paket no
    bas.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // sürüm 1
    bas.push(dcid.len() as u8);
    bas.extend_from_slice(&dcid);
    bas.push(scid.len() as u8);
    bas.extend_from_slice(&scid);
    varint(0, &mut bas); // jeton yok

    // Datagram en az 1200 bayt olmalı; farkı PADDING çerçevesiyle dolduruyoruz.
    // Uzunluk alanı iki bayt (0x4000 kalıbı) olacak kadar büyük olacak.
    let sabit = bas.len() + 2 + PN_UZUNLUK + 16; // +2: uzunluk alanı, +16: etiket
    let dolgu = EN_AZ_DATAGRAM.saturating_sub(sabit + cerceve.len());
    let mut yuk = cerceve;
    yuk.extend(std::iter::repeat_n(0u8, dolgu)); // PADDING

    varint((PN_UZUNLUK + yuk.len() + 16) as u64, &mut bas);
    let pn_konum = bas.len();
    bas.extend_from_slice(&0u32.to_be_bytes()); // paket numarası 0

    // AEAD: nonce = iv XOR paket numarası (sağa dayalı).
    let mut nonce = a.iv;
    let pn = 0u64;
    for i in 0..8 {
        nonce[11 - i] ^= (pn >> (8 * i)) as u8;
    }
    let sifreli = aes128_gcm_sifrele(&a.key, &nonce, &bas, &yuk);

    let mut paket = bas;
    paket.extend_from_slice(&sifreli);

    // Başlık koruması: örnek, paket numarası alanının 4 bayt sonrasından
    // başlayan 16 bayt.
    let ornek_bas = pn_konum + 4;
    let mut ornek = [0u8; 16];
    ornek.copy_from_slice(&paket[ornek_bas..ornek_bas + 16]);
    let maske = Aes128::new(&a.hp).blok_sifrele(&ornek);

    paket[0] ^= maske[0] & 0x0f; // uzun başlıkta alt 4 bit
    for i in 0..PN_UZUNLUK {
        paket[pn_konum + i] ^= maske[1 + i];
    }
    paket
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaz(v: &[u8]) -> String {
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 9001 Ek A.1 — bu değerler standartta yazılı.
    #[test]
    fn anahtarlar_rfc9001_ile_ayni() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let a = anahtarlar(&dcid);
        assert_eq!(yaz(&a.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(yaz(&a.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(yaz(&a.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn varint_kodlamasi() {
        let mut v = Vec::new();
        varint(0, &mut v);
        assert_eq!(v, [0x00]);
        v.clear();
        varint(63, &mut v);
        assert_eq!(v, [0x3f]);
        v.clear();
        varint(64, &mut v);
        assert_eq!(v, [0x40, 0x40]);
        v.clear();
        varint(1182, &mut v);
        assert_eq!(v, [0x44, 0x9e]);
    }

    /// Projenin kendi ayrıştırıcısı kurduğumuz ClientHello'dan adı okuyabilmeli.
    #[test]
    fn kurdugumuz_client_hello_ayristirilabiliyor() {
        let ch = client_hello("ornek.com", 1);
        // ClientHello'yu bir TLS kaydına sararak ayrıştırıcıya veriyoruz.
        let mut kayit = vec![0x16, 0x03, 0x01];
        kayit.extend_from_slice(&(ch.len() as u16).to_be_bytes());
        kayit.extend_from_slice(&ch);
        let sni = trdpi_proxy::clienthello::find_sni(&kayit).expect("ad okunamadı");
        assert_eq!(sni.host, "ornek.com");
    }

    #[test]
    fn farkli_adlar_dogru_okunuyor() {
        for ad in ["a.io", "cok-uzun-bir-alan-adi.example.com", "x.tr"] {
            let ch = client_hello(ad, 7);
            let mut kayit = vec![0x16, 0x03, 0x01];
            kayit.extend_from_slice(&(ch.len() as u16).to_be_bytes());
            kayit.extend_from_slice(&ch);
            assert_eq!(
                trdpi_proxy::clienthello::find_sni(&kayit).unwrap().host,
                ad
            );
        }
    }

    #[test]
    fn datagram_en_az_1200_bayt() {
        // RFC 9000 §14.1: sunucu daha küçük Initial'ı işlemeyebilir.
        for ad in ["a.io", "ornek.com", "cok-uzun-bir-alan-adi.example.com"] {
            let p = sahte_initial(ad, 3);
            assert!(p.len() >= 1200, "{ad}: {} bayt", p.len());
        }
    }

    #[test]
    fn ilk_bayt_korumadan_sonra_initial_gorunumunu_koruyor() {
        let p = sahte_initial("ornek.com", 5);
        // Uzun başlık ve sabit bit korunmalı; koruma yalnızca alt 4 biti
        // değiştiriyor.
        assert_eq!(p[0] & 0xF0, 0xC0);
        assert_eq!(&p[1..5], &[0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn kendi_tespitimiz_bunu_initial_sayiyor() {
        let p = sahte_initial("ornek.com", 9);
        assert!(crate::quic::is_initial(&p));
    }

    #[test]
    fn farkli_tohum_farkli_baglanti_kimligi() {
        let a = sahte_initial("ornek.com", 1);
        let b = sahte_initial("ornek.com", 2);
        // Bağlantı kimlikleri 6. bayttan itibaren.
        assert_ne!(a[6..14], b[6..14]);
    }

    /// Şifreleme gerçekten yapılıyor mu: açık metin pakette görünmemeli.
    #[test]
    fn sunucu_adi_acikta_gitmiyor() {
        let p = sahte_initial("gizli-ad.example", 11);
        assert!(
            !p.windows(16).any(|w| w == b"gizli-ad.example"),
            "sunucu adı şifrelenmemiş"
        );
    }
}
