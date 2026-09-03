//! Ham soket üzerinden paket gönderimi.
//!
//! Sahte paketi çekirdeğin TCP yığınını atlayarak doğrudan göndeririz; aksi
//! halde çekirdek onu kendi bağlantı durumuyla çelişen bir paket sayıp
//! reddederdi.
//!
//! `IP_HDRINCL` ile IP başlığını biz yazarız — TTL'i düşürebilmemizin tek
//! yolu budur.

use std::io;

/// Ham paket göndericisi.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct RawSender {
    fd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl RawSender {
    /// Yeni bir ham soket açar.
    ///
    /// `CAP_NET_RAW` gerektirir; yetki yoksa hata döner.
    #[allow(unsafe_code)]
    pub fn new() -> io::Result<Self> {
        use std::os::fd::FromRawFd;

        // SAFETY: socket() geçerli bir tanımlayıcı ya da -1 döner; -1 durumu
        // aşağıda kontrol ediliyor.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd geçerli ve sahipliği buraya geçiyor.
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

        // IP başlığını biz sağlayacağız.
        let one: libc::c_int = 1;
        // SAFETY: `one` doğru tipte ve boyutu doğru bildiriliyor.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        // Gönderdiğimiz paketleri işaretle ki nftables onları tekrar kuyruğa
        // almasın; işaretlenmezse sahte paket kendi kuyruğumuza düşer ve
        // sonsuz döngü oluşur.
        let mark: libc::c_int = crate::nft::PACKET_MARK as libc::c_int;
        // SAFETY: `mark` doğru tipte ve boyutu doğru bildiriliyor.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&mark as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(RawSender { fd: owned })
    }

    /// Hazır bir IPv4 paketini gönderir.
    ///
    /// Paketin hedef adresi IP başlığından okunur.
    #[allow(unsafe_code)]
    pub fn send(&self, packet: &[u8]) -> io::Result<()> {
        use std::os::fd::AsRawFd;

        if packet.len() < crate::packet::IPV4_MIN_HEADER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "paket IPv4 başlığından kısa",
            ));
        }

        // SAFETY: sıfırlanmış sockaddr_in doğru boyutta.
        let mut dest: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        dest.sin_family = libc::AF_INET as libc::sa_family_t;
        dest.sin_addr.s_addr = u32::from_ne_bytes([packet[16], packet[17], packet[18], packet[19]]);

        // SAFETY: `packet` geçerli bir dilim, `dest` geçerli bir adres yapısı
        // ve boyutları doğru bildiriliyor.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                (&dest as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };

        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Linux dışında ham soket yoktur.
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct RawSender;

#[cfg(not(target_os = "linux"))]
impl RawSender {
    /// Bu platformda kullanılamaz.
    pub fn new() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ham soket yalnızca Linux'ta",
        ))
    }

    /// Bu platformda kullanılamaz.
    pub fn send(&self, _packet: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ham soket yalnızca Linux'ta",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn linux_disinda_desteklenmiyor() {
        let err = RawSender::new().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn yetkisiz_kullanicida_anlamli_hata() {
        // Root değilsek CAP_NET_RAW yoktur ve hata almalıyız; root isek
        // soket açılmalı. İkisi de kabul edilebilir, panik olmamalı.
        match RawSender::new() {
            Ok(_) => {}
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
        }
    }
}
