//! Yerel proxy'yi çalıştırır.
//!
//! ```text
//! cargo run -p trdpi-proxy --bin trdpi-proxy
//! cargo run -p trdpi-proxy --bin trdpi-proxy -- --port 1080 --strateji sni
//! ```
//!
//! Yönetici yetkisi gerektirmez ve sistemde hiçbir şeyi değiştirmez.

use std::net::SocketAddr;
use std::time::Duration;

use trdpi_core::backend::Backend;
use trdpi_core::profile::{FragmentationMode, Profile, RiskLevel};
use trdpi_core::{Mechanism, SessionId};
use trdpi_proxy::{ProxyConfig, ProxyEngine};

fn main() {
    let mut port: u16 = 1080;
    let mut fragmentation = FragmentationMode::SniAware;
    let mut delay_ms: u64 = 12;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse().ok()) {
                    Some(v) => port = v,
                    None => return hata("--port bir port numarası bekliyor"),
                }
            }
            "--strateji" | "-s" => {
                i += 1;
                fragmentation = match args.get(i).map(String::as_str) {
                    Some("sni") => FragmentationMode::SniAware,
                    Some("kapali") => FragmentationMode::Off,
                    Some(v) => match v.strip_prefix("sabit:").and_then(|n| n.parse().ok()) {
                        Some(position) => FragmentationMode::Fixed { position },
                        None => return hata("--strateji: sni | kapali | sabit:<konum>"),
                    },
                    None => return hata("--strateji bir değer bekliyor"),
                };
            }
            "--gecikme" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse().ok()) {
                    Some(v) => delay_ms = v,
                    None => return hata("--gecikme milisaniye bekliyor"),
                }
            }
            "--yardim" | "-h" => return yardim(),
            other => return hata(&format!("bilinmeyen seçenek: {other}")),
        }
        i += 1;
    }

    let mut profile = Profile::baseline();
    profile.name = "Yerel proxy".into();
    profile.risk = RiskLevel::Low;
    profile.supported_mechanisms = vec![Mechanism::LocalProxy];
    profile.strategy.fragmentation = fragmentation;

    let engine = ProxyEngine::new(ProxyConfig {
        bind: SocketAddr::from(([127, 0, 0, 1], port)),
        split_delay: Duration::from_millis(delay_ms),
        ..Default::default()
    });

    let session = SessionId::new();
    let mut snapshot = match engine.prepare(session) {
        Ok(s) => s,
        Err(e) => return hata(&e.user_message()),
    };

    if let Err(e) = engine.apply(&profile, &mut snapshot) {
        return hata(&e.user_message());
    }

    let adres = match engine.address() {
        Some(a) => a,
        None => return hata("proxy başlatıldı ama adres alınamadı"),
    };

    println!("TR-DPI yerel proxy çalışıyor");
    println!();
    println!("  SOCKS5 adresi   {adres}");
    println!("  Strateji        {}", strateji_adi(fragmentation));
    println!("  Parça aralığı   {delay_ms} ms");
    println!();
    println!("Tarayıcını bu SOCKS5 adresine yönlendir.");
    println!("Firefox: Ayarlar → Ağ Ayarları → Elle proxy → SOCKS v5");
    println!("         'SOCKS v5 kullanırken DNS'i proxy üzerinden çöz' işaretli olsun.");
    println!();
    println!("Durdurmak için Ctrl+C.");

    // Bu motor kalıcı sistem durumu bırakmadığı için süreç sonlandığında
    // temizlenecek bir şey kalmaz.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn strateji_adi(m: FragmentationMode) -> String {
    match m {
        FragmentationMode::Off => "kapalı".into(),
        FragmentationMode::SniAware => "SNI ortasından bölme".into(),
        FragmentationMode::Fixed { position } => format!("sabit konum ({position}. bayt)"),
    }
}

fn yardim() {
    println!("TR-DPI yerel proxy");
    println!();
    println!("  --port, -p <port>        dinlenecek port (varsayılan 1080)");
    println!("  --strateji, -s <kip>     sni | kapali | sabit:<konum>  (varsayılan sni)");
    println!("  --gecikme <ms>           parçalar arası bekleme (varsayılan 12)");
    println!("  --yardim, -h             bu metin");
}

fn hata(mesaj: &str) {
    eprintln!("Hata: {mesaj}");
    eprintln!();
    yardim();
    std::process::exit(2);
}
