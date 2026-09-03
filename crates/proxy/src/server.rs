//! Dinleyici ve bağlantı aktarımı.
//!
//! Her bağlantı kendi işlemcisinde (thread) çalışır. Eşzamanlılık modeli
//! kasıtlı olarak basittir: kişisel kullanımda aynı anda onlarca bağlantı olur,
//! binlerce değil.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use trdpi_core::profile::FragmentationMode;

use crate::socks5::{self, Reply};
use crate::split;

/// Proxy ayarları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// Dinlenecek adres. Port `0` verilirse işletim sistemi seçer.
    ///
    /// Daima geri döngü adresine bağlanmalıdır; bu proxy ağdan erişilebilir
    /// olmamalıdır.
    pub bind: SocketAddr,
    /// İlk yazmaya uygulanacak parçalama.
    pub fragmentation: FragmentationMode,
    /// Parçalar arasında beklenecek süre.
    ///
    /// Beklemeden yazılan parçalar çekirdek tarafından tek segmentte
    /// birleştirilebilir; o zaman parçalamanın hiçbir etkisi olmaz.
    pub split_delay: Duration,
    /// Hedefe bağlanma zaman aşımı.
    pub connect_timeout: Duration,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            fragmentation: FragmentationMode::SniAware,
            split_delay: Duration::from_millis(12),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Çalışan bir proxy'nin tutamacı. Düşürüldüğünde dinleyici kapanır.
#[derive(Debug)]
pub struct ProxyHandle {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    stats: Arc<Stats>,
    worker: Option<thread::JoinHandle<()>>,
}

/// Proxy sayaçları.
#[derive(Debug, Default)]
pub struct Stats {
    /// Kabul edilen bağlantı sayısı.
    pub accepted: AtomicU64,
    /// Hedefe ulaşılamayan bağlantı sayısı.
    pub failed: AtomicU64,
    /// Parçalanarak gönderilen ilk yazma sayısı.
    pub fragmented: AtomicU64,
}

impl ProxyHandle {
    /// Dinlenen gerçek adres. Port `0` verilmişse seçilen portu buradan öğren.
    pub fn address(&self) -> SocketAddr {
        self.addr
    }

    /// Sayaçlar.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Dinleyiciyi durdurur ve kabul döngüsünün bitmesini bekler.
    pub fn stop(mut self) {
        self.shutdown_inner();
    }

    fn shutdown_inner(&mut self) {
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return;
        }
        // Kabul döngüsü `accept` üzerinde bloke; kendimize bağlanarak uyandır.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(500));
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.shutdown_inner();
    }
}

/// Proxy'yi başlatır ve dinlemeye geçer.
pub fn start(config: ProxyConfig) -> io::Result<ProxyHandle> {
    let listener = TcpListener::bind(config.bind)?;
    let addr = listener.local_addr()?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Stats::default());

    let worker = {
        let shutdown = Arc::clone(&shutdown);
        let stats = Arc::clone(&stats);
        thread::spawn(move || {
            for incoming in listener.incoming() {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(client) = incoming else { continue };

                let config = config.clone();
                let stats = Arc::clone(&stats);
                stats.accepted.fetch_add(1, Ordering::Relaxed);

                thread::spawn(move || {
                    // Tek bir bağlantının hatası proxy'yi düşürmemeli.
                    if handle_connection(client, &config, &stats).is_err() {
                        stats.failed.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        })
    };

    Ok(ProxyHandle {
        addr,
        shutdown,
        stats,
        worker: Some(worker),
    })
}

fn handle_connection(mut client: TcpStream, config: &ProxyConfig, stats: &Stats) -> io::Result<()> {
    client.set_nodelay(true)?;

    let request = match socks5::accept(&mut client)? {
        Ok(r) => r,
        // Hata yanıtı `accept` içinde yazıldı.
        Err(_) => return Ok(()),
    };

    let authority = request.address.authority(request.port);
    let Some(target) = authority.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
        let _ = client.write_all(&socks5::build_reply(Reply::NetworkUnreachable));
        return Ok(());
    };

    let upstream = match TcpStream::connect_timeout(&target, config.connect_timeout) {
        Ok(s) => s,
        Err(e) => {
            let reply = match e.kind() {
                io::ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                _ => Reply::NetworkUnreachable,
            };
            let _ = client.write_all(&socks5::build_reply(reply));
            return Ok(());
        }
    };

    // Nagle kapalı olmalı; aksi halde parçalar tek segmentte birleşir ve
    // parçalamanın hiçbir anlamı kalmaz.
    upstream.set_nodelay(true)?;
    client.write_all(&socks5::build_reply(Reply::Success))?;

    relay(client, upstream, config, stats)
}

/// İlk yazmayı parçalayarak gönderir, sonrasında iki yönlü aktarım yapar.
fn relay(
    client: TcpStream,
    upstream: TcpStream,
    config: &ProxyConfig,
    stats: &Stats,
) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;

    // İlk parça: ClientHello buradadır.
    let mut first = vec![0u8; 16 * 1024];
    let n = client_read.read(&mut first)?;
    if n == 0 {
        return Ok(());
    }
    first.truncate(n);

    let plan = split::plan(&first, config.fragmentation);
    if plan.len() > 1 {
        stats.fragmented.fetch_add(1, Ordering::Relaxed);
    }
    write_fragments(&mut upstream_write, &plan, config.split_delay)?;

    // Yanıt yönü ayrı bir işlemcide.
    let down = thread::spawn(move || {
        let mut from = upstream;
        let mut to = client;
        let _ = io::copy(&mut from, &mut to);
        let _ = to.shutdown(Shutdown::Write);
    });

    let _ = io::copy(&mut client_read, &mut upstream_write);
    let _ = upstream_write.shutdown(Shutdown::Write);
    let _ = down.join();

    Ok(())
}

/// Parçaları aralarında bekleyerek yazar.
pub fn write_fragments<W: Write>(out: &mut W, parts: &[&[u8]], delay: Duration) -> io::Result<()> {
    for (i, part) in parts.iter().enumerate() {
        out.write_all(part)?;
        out.flush()?;
        // Son parçadan sonra beklemenin anlamı yok.
        if i + 1 < parts.len() && !delay.is_zero() {
            thread::sleep(delay);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varsayilan_yalnizca_geri_donguye_baglaniyor() {
        assert!(ProxyConfig::default().bind.ip().is_loopback());
    }

    #[test]
    fn parcalar_sirayla_yaziliyor() {
        let mut out = Vec::new();
        let parts: Vec<&[u8]> = vec![b"disc", b"ord.com"];

        write_fragments(&mut out, &parts, Duration::ZERO).unwrap();
        assert_eq!(out, b"discord.com");
    }

    #[test]
    fn bos_plan_sorun_cikarmiyor() {
        let mut out = Vec::new();
        write_fragments(&mut out, &[], Duration::ZERO).unwrap();
        assert!(out.is_empty());
    }
}
