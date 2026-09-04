//! DNS paket biçimi.
//!
//! Hazır bir çözümleyici kütüphanesi yerine paketi kendimiz kuruyoruz, çünkü
//! **belirli bir sunucuya belirli bir porttan** sormamız gerekiyor. Sistem
//! çözümleyicisi bunu gizler; oysa ölçtüğümüz hatta 53. port dışarıya kapalı
//! ve çalışan tek yol standart dışı porttan sormak.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Çözümlenmiş bir DNS yanıtı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    /// Dönen A kayıtları.
    pub addresses: Vec<Ipv4Addr>,
    /// Yanıtın RCODE alanı. 0 = NOERROR, 3 = NXDOMAIN.
    pub rcode: u8,
}

/// DNS paketi çözümlenemediğinde döner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    /// Paket beklenenden kısa.
    #[error("DNS paketi eksik")]
    Truncated,
    /// Yanıtın işlem kimliği sorguyla eşleşmiyor.
    #[error("DNS yanıtı sorguyla eşleşmiyor")]
    IdMismatch,
    /// İsim sıkıştırma döngüsü.
    #[error("DNS isminde döngü")]
    NameLoop,
    /// Sorgu adı DNS'te geçerli değil.
    #[error("geçersiz alan adı")]
    InvalidName,
}

/// Bir A kaydı sorgusu paketi kurar.
pub fn build_query(id: u16, name: &str) -> Result<Vec<u8>, DnsError> {
    let mut buf = Vec::with_capacity(64);

    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // standart sorgu, recursion desired
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&[0; 6]); // ANCOUNT, NSCOUNT, ARCOUNT

    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsError::InvalidName);
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // kök

    buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    Ok(buf)
}

/// İsim alanını atlar ve sonraki konumu döner.
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, DnsError> {
    let mut steps = 0;
    loop {
        steps += 1;
        if steps > 128 {
            return Err(DnsError::NameLoop);
        }
        let len = *buf.get(pos).ok_or(DnsError::Truncated)?;
        if len & 0xC0 == 0xC0 {
            // İşaretçi iki bayttır ve isim orada biter.
            return pos.checked_add(2).ok_or(DnsError::Truncated);
        }
        pos = pos
            .checked_add(1 + len as usize)
            .ok_or(DnsError::Truncated)?;
        if len == 0 {
            return Ok(pos);
        }
    }
}

/// Bir DNS yanıtını çözer.
pub fn parse_response(buf: &[u8], expected_id: u16) -> Result<DnsAnswer, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::Truncated);
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != expected_id {
        return Err(DnsError::IdMismatch);
    }

    let rcode = buf[3] & 0x0F;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos = pos.checked_add(4).ok_or(DnsError::Truncated)?; // QTYPE + QCLASS
    }

    let mut addresses = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        let header = buf.get(pos..pos + 10).ok_or(DnsError::Truncated)?;
        let rtype = u16::from_be_bytes([header[0], header[1]]);
        let rdlen = u16::from_be_bytes([header[8], header[9]]) as usize;
        pos += 10;

        let rdata = buf.get(pos..pos + rdlen).ok_or(DnsError::Truncated)?;
        if rtype == 1 && rdlen == 4 {
            addresses.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
        }
        pos += rdlen;
    }

    Ok(DnsAnswer { addresses, rcode })
}

/// Belirtilen çözümleyiciye A kaydı sorar.
pub fn query(resolver: SocketAddr, name: &str, timeout: Duration) -> io::Result<DnsAnswer> {
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
        & 0xFFFF) as u16;

    let packet =
        build_query(id, name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let bind: SocketAddr = if resolver.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.send_to(&packet, resolver)?;

    let mut buf = [0u8; 1500];
    let (len, _) = socket.recv_from(&mut buf)?;

    parse_response(&buf[..len], id).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Türkiye'de sansür yanıtlarıyla ilişkilendirilmiş adresler.
///
/// OONI ölçümlerinde engellenen alan adlarının bu adrese çözümlendiği
/// gözlenmiştir; ölçtüğümüz hatta da tam olarak bu adres dönüyor.
pub const KNOWN_CENSORSHIP_IPS: &[Ipv4Addr] = &[Ipv4Addr::new(195, 175, 254, 2)];

/// Bir yanıtın bilinen sansür adresi içerip içermediği.
pub fn is_censorship_response(answer: &DnsAnswer) -> bool {
    answer
        .addresses
        .iter()
        .any(|ip| KNOWN_CENSORSHIP_IPS.contains(ip))
}

/// İki yanıtın ortak adres taşıyıp taşımadığı.
///
/// Ortak adres yoksa bu bir müdahale sinyalidir — ama CDN'ler bölgeye göre
/// farklı adres döndürebildiği için tek başına kanıt değildir.
pub fn answers_disagree(a: &DnsAnswer, b: &DnsAnswer) -> bool {
    if a.addresses.is_empty() || b.addresses.is_empty() {
        return false;
    }
    !a.addresses.iter().any(|ip| b.addresses.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorgu_paketi_dogru_kuruluyor() {
        let q = build_query(0xABCD, "ornek.test").unwrap();

        assert_eq!(&q[0..2], &[0xAB, 0xCD]);
        assert_eq!(&q[2..4], &[0x01, 0x00], "recursion desired");
        assert_eq!(&q[4..6], &[0x00, 0x01], "tek soru");
        assert_eq!(q[12], 5);
        assert_eq!(&q[13..18], b"ornek");
        assert_eq!(&q[24..28], &[0, 1, 0, 1], "QTYPE=A QCLASS=IN");
    }

    #[test]
    fn bozuk_isim_reddediliyor() {
        assert_eq!(build_query(1, "").unwrap_err(), DnsError::InvalidName);
        assert_eq!(build_query(1, "a..b").unwrap_err(), DnsError::InvalidName);
        assert_eq!(
            build_query(1, &"x".repeat(64)).unwrap_err(),
            DnsError::InvalidName
        );
    }

    fn ornek_yanit(id: u16, ips: &[[u8; 4]]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&0x8180u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&(ips.len() as u16).to_be_bytes());
        b.extend_from_slice(&[0; 4]);

        b.push(5);
        b.extend_from_slice(b"ornek");
        b.push(4);
        b.extend_from_slice(b"test");
        b.push(0);
        b.extend_from_slice(&[0, 1, 0, 1]);

        for ip in ips {
            b.extend_from_slice(&[0xC0, 0x0C]);
            b.extend_from_slice(&[0, 1, 0, 1]);
            b.extend_from_slice(&[0, 0, 0, 60]);
            b.extend_from_slice(&[0, 4]);
            b.extend_from_slice(ip);
        }
        b
    }

    #[test]
    fn yanit_cozumleniyor() {
        let raw = ornek_yanit(0x1234, &[[93, 184, 216, 34], [93, 184, 216, 35]]);
        let ans = parse_response(&raw, 0x1234).unwrap();

        assert_eq!(ans.rcode, 0);
        assert_eq!(ans.addresses.len(), 2);
    }

    #[test]
    fn yanlis_kimlikli_yanit_reddediliyor() {
        let raw = ornek_yanit(0x1234, &[[1, 2, 3, 4]]);
        assert_eq!(
            parse_response(&raw, 0x9999).unwrap_err(),
            DnsError::IdMismatch
        );
    }

    #[test]
    fn kirpilmis_paket_panik_yapmiyor() {
        let raw = ornek_yanit(0x1234, &[[1, 2, 3, 4]]);
        for n in 0..raw.len() {
            let _ = parse_response(&raw[..n], 0x1234);
        }
    }

    /// Ölçtüğümüz hatta sistemin döndürdüğü adres tam olarak budur.
    #[test]
    fn sansur_adresi_taniniyor() {
        let ans = DnsAnswer {
            addresses: vec![Ipv4Addr::new(195, 175, 254, 2)],
            rcode: 0,
        };
        assert!(is_censorship_response(&ans));

        let temiz = DnsAnswer {
            addresses: vec![Ipv4Addr::new(162, 159, 136, 232)],
            rcode: 0,
        };
        assert!(!is_censorship_response(&temiz));
    }

    #[test]
    fn bos_yanit_uyusmazlik_sayilmiyor() {
        let bos = DnsAnswer {
            addresses: vec![],
            rcode: 3,
        };
        let dolu = DnsAnswer {
            addresses: vec![Ipv4Addr::new(1, 1, 1, 1)],
            rcode: 0,
        };
        assert!(!answers_disagree(&bos, &dolu));
        assert!(!answers_disagree(&dolu, &bos));
    }
}
