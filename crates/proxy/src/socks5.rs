//! SOCKS5 sunucu tarafı.
//!
//! Yalnızca `CONNECT` ve kimlik doğrulamasız erişim desteklenir; dinleyici
//! `127.0.0.1`'e bağlandığı için ağdan erişilemez.
//!
//! Ayrıştırma saf fonksiyonlardır ve ağ olmadan test edilir.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// SOCKS5 sürüm baytı.
pub const VERSION: u8 = 0x05;

/// İstemcinin bağlanmak istediği adres.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// Sayısal adres.
    Ip(IpAddr),
    /// Alan adı — SNI ile aynı olduğu için parçalama kararında kullanılır.
    Domain(String),
}

impl Address {
    /// `host:port` biçimi.
    pub fn authority(&self, port: u16) -> String {
        match self {
            Address::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{port}"),
            Address::Ip(IpAddr::V4(ip)) => format!("{ip}:{port}"),
            Address::Domain(d) => format!("{d}:{port}"),
        }
    }
}

/// Çözümlenmiş bir SOCKS5 isteği.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Hedef adres.
    pub address: Address,
    /// Hedef port.
    pub port: u16,
}

/// SOCKS5 yanıt kodları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reply {
    /// Başarılı.
    Success = 0x00,
    /// Genel hata.
    GeneralFailure = 0x01,
    /// Ağ erişilemiyor.
    NetworkUnreachable = 0x03,
    /// Bağlantı reddedildi.
    ConnectionRefused = 0x05,
    /// Desteklenmeyen komut.
    CommandNotSupported = 0x07,
    /// Desteklenmeyen adres tipi.
    AddressNotSupported = 0x08,
}

/// SOCKS5 protokol hataları.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Socks5Error {
    /// Sürüm baytı 0x05 değil.
    #[error("desteklenmeyen SOCKS sürümü")]
    BadVersion,
    /// CONNECT dışında bir komut istendi.
    #[error("yalnızca CONNECT destekleniyor")]
    UnsupportedCommand,
    /// Bilinmeyen adres tipi.
    #[error("desteklenmeyen adres tipi")]
    UnsupportedAddress,
    /// Alan adı geçerli UTF-8 değil.
    #[error("geçersiz alan adı")]
    InvalidDomain,
    /// Paket beklenenden kısa.
    #[error("eksik SOCKS5 paketi")]
    Truncated,
}

impl Socks5Error {
    /// İstemciye dönecek yanıt kodu.
    pub fn reply(&self) -> Reply {
        match self {
            Self::UnsupportedCommand => Reply::CommandNotSupported,
            Self::UnsupportedAddress | Self::InvalidDomain => Reply::AddressNotSupported,
            _ => Reply::GeneralFailure,
        }
    }
}

/// İstemcinin ilk selamlamasını çözer ve önerdiği yöntemleri döner.
pub fn parse_greeting(buf: &[u8]) -> Result<&[u8], Socks5Error> {
    let ver = *buf.first().ok_or(Socks5Error::Truncated)?;
    if ver != VERSION {
        return Err(Socks5Error::BadVersion);
    }
    let n = *buf.get(1).ok_or(Socks5Error::Truncated)? as usize;
    buf.get(2..2 + n).ok_or(Socks5Error::Truncated)
}

/// Bağlantı isteğini çözer.
pub fn parse_request(buf: &[u8]) -> Result<Request, Socks5Error> {
    let head = buf.get(..4).ok_or(Socks5Error::Truncated)?;
    if head[0] != VERSION {
        return Err(Socks5Error::BadVersion);
    }
    if head[1] != 0x01 {
        return Err(Socks5Error::UnsupportedCommand);
    }

    let (address, next) = match head[3] {
        0x01 => {
            let b = buf.get(4..8).ok_or(Socks5Error::Truncated)?;
            (
                Address::Ip(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
                8,
            )
        }
        0x03 => {
            let len = *buf.get(4).ok_or(Socks5Error::Truncated)? as usize;
            let raw = buf.get(5..5 + len).ok_or(Socks5Error::Truncated)?;
            let domain = std::str::from_utf8(raw).map_err(|_| Socks5Error::InvalidDomain)?;
            if domain.is_empty() {
                return Err(Socks5Error::InvalidDomain);
            }
            (Address::Domain(domain.to_owned()), 5 + len)
        }
        0x04 => {
            let b = buf.get(4..20).ok_or(Socks5Error::Truncated)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(b);
            (Address::Ip(IpAddr::V6(Ipv6Addr::from(octets))), 20)
        }
        _ => return Err(Socks5Error::UnsupportedAddress),
    };

    let p = buf.get(next..next + 2).ok_or(Socks5Error::Truncated)?;
    Ok(Request {
        address,
        port: u16::from_be_bytes([p[0], p[1]]),
    })
}

/// Sunucu yanıt paketini kurar.
///
/// Bağlanılan adresi geri bildirmek zorunlu değildir; sıfır adres yaygın ve
/// kabul edilen bir davranıştır.
pub fn build_reply(reply: Reply) -> [u8; 10] {
    [VERSION, reply as u8, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// Bir akış üzerinde SOCKS5 el sıkışmasını tamamlar ve isteği döner.
pub fn accept<S: Read + Write>(stream: &mut S) -> io::Result<Result<Request, Socks5Error>> {
    let mut buf = [0u8; 262];

    let n = stream.read(&mut buf)?;
    if let Err(e) = parse_greeting(&buf[..n]) {
        // Selamlama çözülemezse yöntem müzakeresi de yapılamaz.
        let _ = stream.write_all(&[VERSION, 0xFF]);
        return Ok(Err(e));
    }
    stream.write_all(&[VERSION, 0x00])?; // kimlik doğrulama yok

    let n = stream.read(&mut buf)?;
    match parse_request(&buf[..n]) {
        Ok(req) => Ok(Ok(req)),
        Err(e) => {
            let _ = stream.write_all(&build_reply(e.reply()));
            Ok(Err(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selamlama_cozumleniyor() {
        let methods = parse_greeting(&[0x05, 0x02, 0x00, 0x02]).unwrap();
        assert_eq!(methods, &[0x00, 0x02]);
    }

    #[test]
    fn yanlis_surum_reddediliyor() {
        assert_eq!(
            parse_greeting(&[0x04, 0x01, 0x00]).unwrap_err(),
            Socks5Error::BadVersion
        );
    }

    #[test]
    fn alan_adi_istegi_cozumleniyor() {
        let mut req = vec![0x05, 0x01, 0x00, 0x03, 11];
        req.extend_from_slice(b"discord.com");
        req.extend_from_slice(&443u16.to_be_bytes());

        let parsed = parse_request(&req).unwrap();
        assert_eq!(parsed.address, Address::Domain("discord.com".into()));
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.address.authority(443), "discord.com:443");
    }

    #[test]
    fn ipv4_istegi_cozumleniyor() {
        let req = [0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xBB];
        let parsed = parse_request(&req).unwrap();

        assert_eq!(
            parsed.address,
            Address::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
        );
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn ipv6_istegi_cozumleniyor() {
        let mut req = vec![0x05, 0x01, 0x00, 0x04];
        req.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        req.extend_from_slice(&443u16.to_be_bytes());

        let parsed = parse_request(&req).unwrap();
        assert!(matches!(parsed.address, Address::Ip(IpAddr::V6(_))));
        assert!(parsed.address.authority(443).starts_with('['));
    }

    #[test]
    fn connect_disi_komut_reddediliyor() {
        let req = [0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80]; // BIND
        assert_eq!(
            parse_request(&req).unwrap_err(),
            Socks5Error::UnsupportedCommand
        );
    }

    #[test]
    fn bilinmeyen_adres_tipi_reddediliyor() {
        let req = [0x05, 0x01, 0x00, 0x09, 1, 2];
        assert_eq!(
            parse_request(&req).unwrap_err(),
            Socks5Error::UnsupportedAddress
        );
    }

    #[test]
    fn bos_alan_adi_reddediliyor() {
        let req = [0x05, 0x01, 0x00, 0x03, 0x00, 0x01, 0xBB];
        assert_eq!(parse_request(&req).unwrap_err(), Socks5Error::InvalidDomain);
    }

    /// Kısmi paketler panik yerine hata döndürmeli.
    #[test]
    fn kirpilmis_istek_panik_yapmiyor() {
        let mut req = vec![0x05, 0x01, 0x00, 0x03, 11];
        req.extend_from_slice(b"discord.com");
        req.extend_from_slice(&443u16.to_be_bytes());

        for n in 0..req.len() {
            assert!(parse_request(&req[..n]).is_err(), "n={n}");
        }
        assert!(parse_request(&req).is_ok());
    }

    #[test]
    fn yanit_paketi_dogru() {
        let r = build_reply(Reply::Success);
        assert_eq!(r[0], VERSION);
        assert_eq!(r[1], 0x00);
        assert_eq!(r[3], 0x01, "adres tipi IPv4");
        assert_eq!(r.len(), 10);
    }

    #[test]
    fn hatalar_dogru_yanit_koduna_esleniyor() {
        assert_eq!(
            Socks5Error::UnsupportedCommand.reply(),
            Reply::CommandNotSupported
        );
        assert_eq!(
            Socks5Error::UnsupportedAddress.reply(),
            Reply::AddressNotSupported
        );
        assert_eq!(Socks5Error::Truncated.reply(), Reply::GeneralFailure);
    }
}
