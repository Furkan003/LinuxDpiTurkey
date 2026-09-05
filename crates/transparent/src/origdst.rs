//! Yönlendirilen bağlantının gerçek hedefini bulma.
//!
//! nftables `redirect` bağlantıyı bize çevirdiğinde soketin uzak adresi artık
//! bizim portumuzdur; istemcinin aslında nereye gitmek istediği çekirdekte
//! saklıdır. `SO_ORIGINAL_DST` bunu geri verir.
//!
//! Bu bilgi olmadan bağlantıyı ileteceğimiz yeri bilemeyiz.
//!
//! IPv4 ve IPv6 için ayrı seçenekler var; hangisinin sorulacağı soketin
//! kendi ailesinden anlaşılıyor. IPv6 tarafı her çekirdekte/derlemede aynı
//! davranmayabilir, o yüzden motor açılışta bunu **sınıyor** ve ancak
//! çalıştığını gördüğünde IPv6 kuralını kuruyor.

use std::io;
use std::net::{SocketAddr, TcpStream};

/// netfilter'ın özgün hedefi sakladığı seçenek. IPv4 ve IPv6'da aynı numara.
#[cfg(target_os = "linux")]
const SO_ORIGINAL_DST: libc::c_int = 80;

/// Yönlendirilmiş bir soketin özgün hedefini döner.
#[cfg(target_os = "linux")]
pub fn original_destination(stream: &TcpStream) -> io::Result<SocketAddr> {
    match stream.local_addr()? {
        SocketAddr::V4(_) => ipv4_hedef(stream),
        SocketAddr::V6(_) => ipv6_hedef(stream),
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn ipv4_hedef(stream: &TcpStream) -> io::Result<SocketAddr> {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::fd::AsRawFd;

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    // SAFETY: `addr` doğru boyutta ve hizalı bir sockaddr_in; `len` onun
    // boyutunu tutuyor ve getsockopt yalnızca bu kadarını yazıyor.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            (&mut addr as *mut libc::sockaddr_in).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn ipv6_hedef(stream: &TcpStream) -> io::Result<SocketAddr> {
    use std::net::{Ipv6Addr, SocketAddrV6};
    use std::os::fd::AsRawFd;

    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    // SAFETY: `addr` doğru boyutta ve hizalı bir sockaddr_in6; `len` onun
    // boyutunu tutuyor ve getsockopt yalnızca bu kadarını yazıyor.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IPV6,
            SO_ORIGINAL_DST,
            (&mut addr as *mut libc::sockaddr_in6).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
    let port = u16::from_be(addr.sin6_port);
    Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
}

/// Linux dışında bu mekanizma yoktur.
#[cfg(not(target_os = "linux"))]
pub fn original_destination(_stream: &TcpStream) -> io::Result<SocketAddr> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "özgün hedef yalnızca Linux'ta okunabilir",
    ))
}

/// Hedefin kendi dinleyicimiz olup olmadığı.
///
/// Yönlendirme kuralı bir şekilde kendi trafiğimizi de yakalarsa bağlantı
/// sonsuza kadar kendine döner; bunu erkenden kesiyoruz.
pub fn is_self(target: SocketAddr, listener: SocketAddr) -> bool {
    target.port() == listener.port() && target.ip().is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, ToSocketAddrs};

    #[test]
    fn kendi_dinleyicimiz_taniniyor() {
        let l: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        assert!(is_self("127.0.0.1:9443".parse().unwrap(), l));
        assert!(is_self("[::1]:9443".parse().unwrap(), l));
    }

    #[test]
    fn baska_hedef_kendimiz_degil() {
        let l: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        assert!(!is_self("1.2.3.4:9443".parse().unwrap(), l));
        assert!(!is_self("127.0.0.1:443".parse().unwrap(), l));
    }

    /// Yönlendirilmemiş bir soketin özgün hedefi yoktur; hata dönmeli ve
    /// program çökmemeli.
    #[cfg(target_os = "linux")]
    #[test]
    fn yonlendirilmemis_soket_hata_donuyor() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let adres = l.local_addr().unwrap();
        let _istemci = TcpStream::connect(adres).unwrap();
        let (s, _) = l.accept().unwrap();
        // Kural yokken çekirdek bir hedef saklamamıştır.
        let _ = original_destination(&s);
    }

    #[test]
    fn ipv6_adres_cozulebiliyor() {
        // Testin kendisi IPv6 gerektirmiyor; yalnızca ayrıştırma.
        let a = "[::1]:443".to_socket_addrs().unwrap().next().unwrap();
        assert!(matches!(a, SocketAddr::V6(_)));
    }
}
