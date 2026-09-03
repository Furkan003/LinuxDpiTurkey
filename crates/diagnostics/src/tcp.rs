//! TCP bağlantı ölçümü.
//!
//! Amaç yalnızca "bağlandı mı" değil, **nasıl başarısız olduğu**: reddedilen
//! bağlantı, sıfırlanan bağlantı ve zaman aşımı farklı sansür mekanizmalarına
//! işaret eder.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use trdpi_core::Classification;

/// Bir TCP bağlantı denemesinin sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOutcome {
    /// Bağlantı kuruldu.
    Connected,
    /// Karşı taraf açıkça reddetti (RST, port kapalı).
    ///
    /// Sansürden çok "sunucu yok" anlamına gelir.
    Refused,
    /// Bağlantı kurulduktan sonra sıfırlandı.
    Reset,
    /// Yanıt hiç gelmedi.
    TimedOut,
    /// Yol bulunamadı — genelde yerel ağ sorunu.
    Unreachable,
}

impl TcpOutcome {
    /// Bir I/O hatasını sınıflandırır.
    pub fn from_error(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::ConnectionRefused => Self::Refused,
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => Self::Reset,
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Self::TimedOut,
            _ => {
                // Windows ve Linux farklı ErrorKind'lar üretebiliyor; ham koda bak.
                match err.raw_os_error() {
                    Some(10060) | Some(110) => Self::TimedOut,
                    Some(10054) | Some(104) => Self::Reset,
                    Some(10061) | Some(111) => Self::Refused,
                    Some(10065) | Some(113) | Some(101) => Self::Unreachable,
                    _ => Self::Unreachable,
                }
            }
        }
    }

    /// Bu sonucun işaret ettiği ağ davranışı.
    pub fn classify(self) -> Classification {
        match self {
            Self::Connected => Classification::Healthy,
            Self::Reset => Classification::TcpReset,
            Self::TimedOut => Classification::Timeout,
            // Reddedilen bağlantı ve erişilemeyen yol sansür kanıtı değildir.
            Self::Refused | Self::Unreachable => Classification::Unknown,
        }
    }

    /// Bağlantının kurulup kurulmadığı.
    pub fn is_success(self) -> bool {
        self == Self::Connected
    }
}

/// Bir TCP bağlantısı kurmayı dener ve süresini ölçer.
///
/// Bağlantı kurulursa akış geri döner; TLS ölçümü onun üzerinden devam eder.
pub fn connect(addr: SocketAddr, timeout: Duration) -> (TcpOutcome, Duration, Option<TcpStream>) {
    let started = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(stream) => (TcpOutcome::Connected, started.elapsed(), Some(stream)),
        Err(e) => (TcpOutcome::from_error(&e), started.elapsed(), None),
    }
}

/// Gecikmeyi 0.0–1.0 aralığında bir sağlık değerine çevirir.
///
/// `good` altındaki her süre 1.0, `bad` üstündeki her süre 0.0 sayılır; arası
/// doğrusaldır. Eşikler ölçümle kalibre edilmelidir.
pub fn latency_health(observed: Duration, good: Duration, bad: Duration) -> f64 {
    debug_assert!(good < bad);
    if observed <= good {
        return 1.0;
    }
    if observed >= bad {
        return 0.0;
    }
    let span = (bad - good).as_secs_f64();
    if span <= 0.0 {
        return 0.0;
    }
    1.0 - ((observed - good).as_secs_f64() / span)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reddedilen_baglanti_sansur_sayilmiyor() {
        // Kapalı port "engellendi" demek değildir.
        assert_eq!(TcpOutcome::Refused.classify(), Classification::Unknown);
        assert_eq!(TcpOutcome::Unreachable.classify(), Classification::Unknown);
    }

    #[test]
    fn reset_ve_timeout_ayri_siniflar() {
        assert_eq!(TcpOutcome::Reset.classify(), Classification::TcpReset);
        assert_eq!(TcpOutcome::TimedOut.classify(), Classification::Timeout);
    }

    #[test]
    fn hata_turleri_dogru_esleniyor() {
        let cases = [
            (io::ErrorKind::ConnectionRefused, TcpOutcome::Refused),
            (io::ErrorKind::ConnectionReset, TcpOutcome::Reset),
            (io::ErrorKind::ConnectionAborted, TcpOutcome::Reset),
            (io::ErrorKind::TimedOut, TcpOutcome::TimedOut),
        ];
        for (kind, expected) in cases {
            let err = io::Error::new(kind, "test");
            assert_eq!(TcpOutcome::from_error(&err), expected, "{kind:?}");
        }
    }

    #[test]
    fn ham_os_kodlari_taniniyor() {
        // Windows WSAETIMEDOUT ve Linux ETIMEDOUT
        for code in [10060, 110] {
            let err = io::Error::from_raw_os_error(code);
            assert_eq!(TcpOutcome::from_error(&err), TcpOutcome::TimedOut, "{code}");
        }
        for code in [10054, 104] {
            let err = io::Error::from_raw_os_error(code);
            assert_eq!(TcpOutcome::from_error(&err), TcpOutcome::Reset, "{code}");
        }
    }

    #[test]
    fn gecikme_sagligi_araliginda() {
        let good = Duration::from_millis(100);
        let bad = Duration::from_millis(2000);

        assert_eq!(latency_health(Duration::from_millis(50), good, bad), 1.0);
        assert_eq!(latency_health(Duration::from_millis(3000), good, bad), 0.0);

        let orta = latency_health(Duration::from_millis(1050), good, bad);
        assert!((0.4..0.6).contains(&orta), "{orta}");
    }

    #[test]
    fn kapali_porta_baglanti_basarisiz() {
        // 127.0.0.1:1 gerçekçi biçimde kapalı; ağ erişimi gerektirmez.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (outcome, _, stream) = connect(addr, Duration::from_millis(500));

        assert!(!outcome.is_success());
        assert!(stream.is_none());
        assert!(
            !outcome.classify().is_interference(),
            "yerel red sansür değil"
        );
    }
}
