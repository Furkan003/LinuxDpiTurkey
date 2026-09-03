//! ClientHello çözümlemesi.
//!
//! Parçalamayı SNI'ın *ortasından* yapabilmek için alan adının paketin
//! neresinde olduğunu bilmemiz gerekir. Bu modül bunu bulur.
//!
//! Tümü saf fonksiyondur ve bozuk girdide panik yerine `None` döner — girdi
//! ağdan geldiği için hiçbir varsayım yapılamaz.

use std::ops::Range;

/// TLS handshake kaydı içindeki SNI alanı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniLocation {
    /// Alan adının kayıt içindeki bayt aralığı.
    pub range: Range<usize>,
    /// Alan adı.
    pub host: String,
}

/// İki baytlık büyük-endian sayıyı okur.
fn be16(buf: &[u8], pos: usize) -> Option<usize> {
    let b = buf.get(pos..pos + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]) as usize)
}

/// Verilen baytların bir TLS handshake kaydı olup olmadığı.
pub fn is_client_hello(buf: &[u8]) -> bool {
    buf.len() > 5 && buf[0] == 0x16 && buf[1] == 0x03 && buf.get(5) == Some(&0x01)
}

/// Bir TLS kaydı içinde SNI alanını bulur.
///
/// Dönen aralık, `record` diliminin başına göre mutlak konumdur.
pub fn find_sni(record: &[u8]) -> Option<SniLocation> {
    if !is_client_hello(record) {
        return None;
    }

    // Kayıt başlığı (5) + handshake başlığı (4) + legacy_version (2) + random (32)
    let mut pos = 5 + 4 + 2 + 32;

    // session_id
    let sid_len = *record.get(pos)? as usize;
    pos = pos.checked_add(1 + sid_len)?;

    // cipher_suites
    let cs_len = be16(record, pos)?;
    pos = pos.checked_add(2 + cs_len)?;

    // compression_methods
    let cm_len = *record.get(pos)? as usize;
    pos = pos.checked_add(1 + cm_len)?;

    // extensions
    let ext_total = be16(record, pos)?;
    pos = pos.checked_add(2)?;
    // Gerçek bir ClientHello MSS'i aşabilir ve birden fazla TCP paketine
    // bölünür. Elimizde kaydın yalnızca ilk parçası olsa bile SNI o parçada
    // olabilir; bu yüzden eksik kayıtta pes etmiyoruz, elimizdeki kadarını
    // tarıyoruz. Bu kontrol katıyken gerçek trafikte SNI hiç bulunamıyordu.
    let ext_end = pos.checked_add(ext_total)?.min(record.len());

    while pos + 4 <= ext_end {
        let ext_type = be16(record, pos)?;
        let ext_len = be16(record, pos + 2)?;
        let body = pos + 4;
        let body_end = body.checked_add(ext_len)?;
        if body_end > ext_end {
            return None;
        }

        if ext_type == 0x0000 {
            // server_name: list_len(2) entry_type(1) name_len(2) name
            let mut p = body.checked_add(2)?;
            while p + 3 <= body_end {
                let entry_type = *record.get(p)?;
                let name_len = be16(record, p + 1)?;
                let name_start = p + 3;
                let name_end = name_start.checked_add(name_len)?;
                if name_end > body_end {
                    return None;
                }
                if entry_type == 0x00 {
                    let host = std::str::from_utf8(record.get(name_start..name_end)?).ok()?;
                    return Some(SniLocation {
                        range: name_start..name_end,
                        host: host.to_owned(),
                    });
                }
                p = name_end;
            }
            return None;
        }

        pos = body_end;
    }

    None
}

/// Testlerin paylaştığı ClientHello üreticisi.
#[cfg(test)]
pub(crate) mod tests_support {
    /// Test girdisi olarak gerçek bir ClientHello kurar.
    ///
    /// `trdpi-diagnostics` içindeki üreticiyle aynı yapıyı kullanır; crate'ler
    /// arası bağımlılık yaratmamak için kopyalanmıştır.
    pub fn client_hello(sni: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xAA; 32]); // random
        body.push(32);
        body.extend_from_slice(&[0xBB; 32]); // session_id

        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]); // compression

        let mut ext = Vec::new();

        // Önce SNI olmayan bir uzantı koy ki tarama gerçekten çalışsın.
        ext.extend_from_slice(&0x000Au16.to_be_bytes());
        ext.extend_from_slice(&4u16.to_be_bytes());
        ext.extend_from_slice(&[0x00, 0x02, 0x00, 0x1D]);

        let host = sni.as_bytes();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni_ext.push(0x00);
        sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host);

        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        ext.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext);

        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01];
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::client_hello;
    use super::*;

    #[test]
    fn sni_bulunuyor() {
        let rec = client_hello("discord.com");
        let loc = find_sni(&rec).expect("SNI bulunamadı");

        assert_eq!(loc.host, "discord.com");
        assert_eq!(&rec[loc.range.clone()], b"discord.com");
    }

    #[test]
    fn farkli_uzunluktaki_isimler_bulunuyor() {
        for host in [
            "a.co",
            "www.instagram.com",
            "cok-uzun-bir-alan-adi.example.test",
        ] {
            let rec = client_hello(host);
            let loc = find_sni(&rec).unwrap_or_else(|| panic!("{host} bulunamadı"));
            assert_eq!(loc.host, host);
            assert_eq!(&rec[loc.range], host.as_bytes());
        }
    }

    #[test]
    fn client_hello_olmayan_veri_reddediliyor() {
        assert!(find_sni(b"GET / HTTP/1.1\r\n").is_none());
        assert!(find_sni(&[]).is_none());
        assert!(find_sni(&[0x16, 0x03, 0x01, 0x00, 0x05]).is_none());
        // Handshake ama client_hello değil (0x02 = server_hello)
        assert!(find_sni(&[0x16, 0x03, 0x01, 0x00, 0x10, 0x02]).is_none());
    }

    /// Ağdan gelen bozuk veri hiçbir koşulda panik üretmemeli.
    #[test]
    fn kirpilmis_paket_panik_yapmiyor() {
        let rec = client_hello("discord.com");
        for n in 0..rec.len() {
            let _ = find_sni(&rec[..n]);
        }
    }

    #[test]
    fn bozulmus_uzunluk_alanlari_panik_yapmiyor() {
        let base = client_hello("discord.com");
        for i in 0..base.len().min(80) {
            for value in [0x00u8, 0x01, 0x7F, 0xFF] {
                let mut bozuk = base.clone();
                bozuk[i] = value;
                let _ = find_sni(&bozuk);
            }
        }
    }

    #[test]
    fn is_client_hello_ayirt_ediyor() {
        assert!(is_client_hello(&client_hello("a.co")));
        assert!(!is_client_hello(b"HTTP/1.1 200 OK"));
        assert!(!is_client_hello(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x01]));
    }
}

#[cfg(test)]
mod gercek_paket_testleri {
    use super::*;

    /// curl'ün gerçekten gönderdiği bir ClientHello.
    ///
    /// Sentetik test verisi küçük olduğu için eksik kayıt durumunu hiç
    /// yakalamamıştı; bu dosya onu yakalar.
    const GERCEK: &[u8] = include_bytes!("../tests/data/clienthello-gercek.bin");

    #[test]
    fn gercek_client_hello_taniniyor() {
        assert!(is_client_hello(GERCEK));
        let loc = find_sni(GERCEK).expect("gerçek pakette SNI bulunamadı");
        assert_eq!(loc.host, "discord.com");
        assert_eq!(&GERCEK[loc.range], b"discord.com");
    }

    /// Gerçek ClientHello MSS'i aşıyor ve ağda bölünüyor. İlk parçada SNI
    /// varsa bulunmalı — bu, motorun gerçek trafikte çalışmamasının sebebiydi.
    #[test]
    fn eksik_kayitta_da_sni_bulunuyor() {
        assert!(GERCEK.len() > 1460, "paket MSS'i aşmıyor, test anlamsız");

        let ilk_parca = &GERCEK[..1460];
        let loc = find_sni(ilk_parca).expect("eksik kayıtta SNI bulunamadı");
        assert_eq!(loc.host, "discord.com");
    }

    /// SNI'dan önce kesilmişse bulunamaz — uydurmak yerine None dönmeli.
    #[test]
    fn sni_gelmeden_kesilmisse_bulunamiyor() {
        assert!(find_sni(&GERCEK[..100]).is_none());
    }

    #[test]
    fn her_kesim_noktasinda_panik_yok() {
        for n in 0..GERCEK.len() {
            let _ = find_sni(&GERCEK[..n]);
        }
    }
}
