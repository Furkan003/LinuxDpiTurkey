//! Yönlendirilen bağlantının gerçek hedefini bulma.
//!
//! nftables `redirect` bağlantıyı bize çevirdiğinde soketin uzak adresi artık
//! bizim portumuzdur; istemcinin aslında nereye gitmek istediği çekirdekte
//! saklıdır. `SO_ORIGINAL_DST` bunu geri verir.
//!
//! Bu bilgi olmadan bağlantıyı ileteceğimiz yeri bilemeyiz.

use std::io;
use std::net::{SocketAddr, TcpStream};

/// Yönlendirilmiş bir soketin özgün hedefini döner.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn original_destination(stream: &TcpStream) -> io::Result<SocketAddr> {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::fd::AsRawFd;

    // netfilter'ın özgün hedefi sakladığı seçenek.
    const SO_ORIGINAL_DST: libc::c_int = 80;

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

/// Linux dışında bu mekanizma yoktur.
#[cfg(not(target_os = "linux"))]
pub fn original_destination(_stream: &TcpStream) -> io::Result<SocketAddr> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_ORIGINAL_DST yalnızca Linux'ta bulunur",
    ))
}

/// Hedefin kendi dinleyicimiz olup olmadığı.
///
/// Yönlendirme kuralları düzgünse bu asla olmamalıdır; olursa bağlantıyı
/// kapatmak sonsuz döngüyü önler.
pub fn is_self(target: SocketAddr, listener: SocketAddr) -> bool {
    target.port() == listener.port() && target.ip().is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kendi_dinleyicimize_yonlenme_tespit_ediliyor() {
        let listener: SocketAddr = "127.0.0.1:9443".parse().unwrap();

        assert!(is_self("127.0.0.1:9443".parse().unwrap(), listener));
        assert!(!is_self("93.184.216.34:443".parse().unwrap(), listener));
        assert!(!is_self("127.0.0.1:443".parse().unwrap(), listener));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn linux_disinda_desteklenmiyor_hatasi_veriyor() {
        use std::net::TcpListener;

        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let s = TcpStream::connect(l.local_addr().unwrap()).unwrap();

        let err = original_destination(&s).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
