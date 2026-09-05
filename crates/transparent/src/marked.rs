//! İşaretli giden bağlantı.
//!
//! ## Neden gerekli
//!
//! Yönlendirme kuralı kendi trafiğimizi de yakalarsa bağlantı sonsuza kadar
//! kendine döner. Bunu şimdiye kadar "motorun kullanıcı kimliğini muaf tut"
//! diyerek çözüyorduk — ama motor root çalıştığı için bu, **root olarak
//! çalışan her uygulamayı** kapsam dışı bırakıyordu. `apt`, sistem servisleri
//! ve `sudo` ile çalıştırılan her şey korumasız kalıyordu.
//!
//! Doğrusu: yalnızca **bizim açtığımız soketleri** muaf tutmak. Giden sokete
//! bir işaret koyuyoruz ve nftables o işareti muaf tutuyor. Böylece döngü
//! korunuyor ama root'un geri kalan trafiği kapsama giriyor.
//!
//! ## Geri düşüş
//!
//! `SO_MARK` `CAP_NET_ADMIN` istiyor. Motor root çalıştığı için normalde var,
//! ama kısıtlı bir kapsayıcıda olmayabilir. O yüzden motor açılışta bunu
//! **sınıyor**; çalışmıyorsa eski kullanıcı kimliği muafiyetine dönülüyor.
//! Kapsam daralır ama hiçbir şey bozulmaz.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Giden bağlantılarımıza konan işaret.
///
/// nfqueue motorunun işaretinden farklı bir değer: ikisi aynı makinede
/// çalışabiliyor ve kuralları birbirine karışmamalı.
pub const CONNECT_MARK: u32 = 0x5444_5002;

/// `SO_MARK` kullanılabiliyor mu?
///
/// Bir soket açıp işareti koymayı deniyor. Başarısızsa çağıran taraf
/// kullanıcı kimliği muafiyetine dönmeli.
#[cfg(target_os = "linux")]
pub fn mark_supported() -> bool {
    use std::net::TcpListener;
    // Herhangi bir TCP soketi yeterli; bağlanmıyoruz.
    let Ok(l) = TcpListener::bind("127.0.0.1:0") else {
        return false;
    };
    set_mark(&l, CONNECT_MARK).is_ok()
}

#[cfg(not(target_os = "linux"))]
pub fn mark_supported() -> bool {
    false
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn set_mark<T: std::os::fd::AsFd>(sock: &T, mark: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let deger = mark as libc::c_int;
    // SAFETY: `deger` doğru tipte, boyutu doğru bildiriliyor ve soket
    // tanımlayıcısı çağrı boyunca canlı.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_fd().as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&deger as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// İşaretli bir soketle bağlanır.
///
/// `TcpStream::connect_timeout` soketi kendi açtığı için araya girip işaret
/// koyamıyoruz; soketi elle açıp bağlanmak zorundayız. Zaman aşımı için
/// bloklamayan bağlanma + `poll` kullanılıyor.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn connect_timeout(target: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    use std::os::fd::{FromRawFd, OwnedFd};

    let domain = match target {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };

    // SAFETY: socket() geçerli bir tanımlayıcı ya da -1 döner; -1 aşağıda
    // kontrol ediliyor.
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd geçerli ve sahipliği buraya geçiyor; bundan sonra düşürülmesi
    // kapatılmasını sağlıyor.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    set_mark(&owned, CONNECT_MARK)?;

    let (sa, sa_len) = sockaddr(target);
    // SAFETY: `sa` hedefin ailesine uygun doldurulmuş bir sockaddr; `sa_len`
    // onun gerçek boyutu.
    let rc = unsafe { libc::connect(fd, (&sa as *const libc::sockaddr_storage).cast(), sa_len) };
    if rc != 0 {
        let hata = io::Error::last_os_error();
        if hata.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(hata);
        }
        bekle(fd, timeout)?;
    }

    // Bloklamayan bayrağı kaldır: aktarım kodu bloklayan soket bekliyor.
    // SAFETY: fd geçerli; yalnızca bayrakları okuyup yazıyoruz.
    let bayraklar = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if bayraklar < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: aynı gerekçe.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, bayraklar & !libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(TcpStream::from(owned))
}

/// Bağlanmanın tamamlanmasını bekler ve sonucunu okur.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn bekle(fd: libc::c_int, timeout: Duration) -> io::Result<()> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;

    // SAFETY: tek elemanlı geçerli bir pollfd dizisi veriliyor.
    let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if rc == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "bağlanma zaman aşımına uğradı",
        ));
    }

    // Yazılabilir olması tek başına başarı demek değil; hatayı soketten
    // okumak gerekiyor.
    let mut hata: libc::c_int = 0;
    let mut uzunluk = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `hata` doğru tipte ve `uzunluk` onun boyutunu tutuyor.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut hata as *mut libc::c_int).cast(),
            &mut uzunluk,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if hata != 0 {
        return Err(io::Error::from_raw_os_error(hata));
    }
    Ok(())
}

/// `SocketAddr`'ı çekirdeğin beklediği yapıya çevirir.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sıfırlanmış sockaddr_storage geçerli bir başlangıç durumu.
    let mut depo: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(a) => {
            let uzunluk = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            // SAFETY: depo, sockaddr_in'i içerecek kadar büyük ve hizalı.
            let s = unsafe { &mut *(&mut depo as *mut _ as *mut libc::sockaddr_in) };
            s.sin_family = libc::AF_INET as libc::sa_family_t;
            s.sin_port = a.port().to_be();
            s.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
            (depo, uzunluk)
        }
        SocketAddr::V6(a) => {
            let uzunluk = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            // SAFETY: depo, sockaddr_in6'yı içerecek kadar büyük ve hizalı.
            let s = unsafe { &mut *(&mut depo as *mut _ as *mut libc::sockaddr_in6) };
            s.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            s.sin6_port = a.port().to_be();
            s.sin6_addr.s6_addr = a.ip().octets();
            s.sin6_scope_id = a.scope_id();
            (depo, uzunluk)
        }
    }
}

/// Linux dışında işaret koyamayız; olağan bağlanma kullanılır.
#[cfg(not(target_os = "linux"))]
pub fn connect_timeout(target: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    TcpStream::connect_timeout(&target, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn isaret_nfqueue_isaretinden_farkli() {
        // İki motor aynı anda çalışabiliyor; kuralları karışmamalı.
        assert_ne!(CONNECT_MARK, 0x5444_5001);
    }

    #[test]
    fn yerel_baglanti_kuruluyor() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let adres = l.local_addr().unwrap();
        let s = connect_timeout(adres, Duration::from_secs(2)).expect("bağlanamadı");
        assert_eq!(s.peer_addr().unwrap(), adres);
        // Aktarım kodu bloklayan soket bekliyor.
        assert!(s.set_nodelay(true).is_ok());
    }

    #[test]
    fn kapali_kapi_hata_donuyor() {
        // Dinleyen yoksa bağlanma reddedilmeli; zaman aşımına düşmemeli.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let adres = l.local_addr().unwrap();
        drop(l);
        let sonuc = connect_timeout(adres, Duration::from_secs(2));
        assert!(sonuc.is_err());
    }

    #[test]
    fn ipv6_yerel_baglanti() {
        let Ok(l) = TcpListener::bind("[::1]:0") else {
            return; // IPv6 kapalıysa test atlanır
        };
        let adres = l.local_addr().unwrap();
        let s = connect_timeout(adres, Duration::from_secs(2)).expect("IPv6 bağlanamadı");
        assert_eq!(s.peer_addr().unwrap(), adres);
    }

    #[test]
    fn ulasilamayan_adres_zaman_asimina_ugruyor() {
        // Yönlendirilmeyen, yanıt vermeyen bir adres.
        let hedef: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let basladi = std::time::Instant::now();
        let sonuc = connect_timeout(hedef, Duration::from_millis(300));
        assert!(sonuc.is_err());
        assert!(
            basladi.elapsed() < Duration::from_secs(3),
            "zaman aşımı uygulanmadı"
        );
    }
}
