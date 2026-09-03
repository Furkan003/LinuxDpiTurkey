//! Sahte paket + TTL korumasını çalıştırır.
//!
//! ```text
//! sudo trdpi
//! sudo trdpi --ttl 3
//! sudo trdpi --temizle
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use trdpi_core::backend::Backend;
use trdpi_core::profile::TtlMode;
use trdpi_core::SessionId;
use trdpi_nfqueue::{default_profile, NfqueueConfig, NfqueueEngine};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--yardim" || a == "-h") {
        return yardim();
    }

    let silinen = temizle_yetimler();
    if silinen > 0 {
        println!("Önceki çalışmadan kalan {silinen} kural temizlendi.");
    }
    if args.iter().any(|a| a == "--temizle") {
        println!("Temizlik tamamlandı.");
        return;
    }

    let mut ttl: u8 = 5;
    let mut queue_num: u16 = 4200;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ttl" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u8>().ok()) {
                    Some(v) if v >= 1 => ttl = v,
                    _ => return hata("--ttl 1-255 arası bir sayı bekliyor"),
                }
            }
            "--kuyruk" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse().ok()) {
                    Some(v) => queue_num = v,
                    None => return hata("--kuyruk bir sayı bekliyor"),
                }
            }
            other => return hata(&format!("bilinmeyen seçenek: {other}")),
        }
        i += 1;
    }

    let mut profile = default_profile();
    profile.strategy.ttl = TtlMode::Fixed { hops: ttl };

    let engine = NfqueueEngine::new(NfqueueConfig {
        queue_num,
        ..Default::default()
    });

    let mut snapshot = match engine.prepare(SessionId::new()) {
        Ok(s) => s,
        Err(e) => return hata(&e.user_message()),
    };

    if let Err(e) = engine.apply(&profile, &mut snapshot) {
        return hata(&e.user_message());
    }

    println!();
    println!("Koruma aktif. Tüm uygulamalar kapsam içinde.");
    println!();
    println!("  Yöntem      düşük TTL'li sahte paket");
    println!("  TTL         {ttl}");
    println!("  Kuyruk      {queue_num}");
    println!();
    println!("Site açılmıyorsa --ttl değerini değiştirmeyi dene (3, 5, 7).");
    println!("Durdurmak için Ctrl+C.");

    let dur = Arc::new(AtomicBool::new(false));
    sinyal_kur(Arc::clone(&dur));

    let mut son_rapor = std::time::Instant::now();
    while !dur.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));

        if son_rapor.elapsed() >= Duration::from_secs(15) {
            let s = engine.stats();
            if s.seen > 0 {
                println!(
                    "  paket: {} · sahte: {} · hata: {}",
                    s.seen,
                    s.faked,
                    s.errors()
                );
            }
            son_rapor = std::time::Instant::now();
        }
    }

    let s = engine.stats();
    println!();
    println!(
        "Toplam — paket: {} · sahte gönderilen: {} · kurulamadı: {} · gönderilemedi: {}",
        s.seen, s.faked, s.build_errors, s.send_errors
    );
    if s.seen == 0 {
        println!("Hiç paket görülmedi; kuyruk kuralı çalışmamış olabilir.");
    } else if s.faked == 0 {
        println!("Hiç sahte paket gönderilemedi; koruma etkin olmamış.");
    }

    println!("Kurallar geri alınıyor...");
    match engine.rollback(snapshot) {
        Ok(()) => println!("Temiz."),
        Err(e) => {
            eprintln!("{}", e.user_message());
            eprintln!("Kurtarma:  sudo trdpi --temizle");
            std::process::exit(1);
        }
    }
}

/// Önceki çalışmalardan kalan kendi tablolarımızı siler.
///
/// Kuyruk kuralı `bypass` taşıdığı için kalıntı kural trafiği kesmez; yine de
/// temiz bırakmak doğrusudur.
fn temizle_yetimler() -> usize {
    #[cfg(target_os = "linux")]
    {
        use trdpi_core::SessionId;
        use trdpi_nfqueue::nft;

        let Ok(listing) = nft::run(&["list".to_string(), "tables".to_string()]) else {
            return 0;
        };

        let mut silinen = 0;
        for line in listing.lines() {
            let mut parts = line.split_whitespace();
            if parts.next() != Some("table") {
                continue;
            }
            let (Some(family), Some(name)) = (parts.next(), parts.next()) else {
                continue;
            };
            if !SessionId::is_owned_by_app(name) {
                continue;
            }
            let cmd: Vec<String> = ["delete", "table", family, name]
                .iter()
                .map(|s| s.to_string())
                .collect();
            if nft::run(&cmd).is_ok() {
                silinen += 1;
            }
        }
        silinen
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Ctrl+C ve kapatma sinyallerini yakalar.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn sinyal_kur(dur: Arc<AtomicBool>) {
    use std::sync::OnceLock;
    static BAYRAK: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    let _ = BAYRAK.set(dur);

    extern "C" fn isle(_sig: libc::c_int) {
        if let Some(b) = BAYRAK.get() {
            b.store(true, Ordering::SeqCst);
        }
    }

    // SAFETY: yalnızca atomik bir bayrak yazan, async-signal-safe işleyici.
    unsafe {
        libc::signal(libc::SIGINT, isle as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, isle as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, isle as *const () as libc::sighandler_t);
    }
}

#[cfg(not(target_os = "linux"))]
fn sinyal_kur(_dur: Arc<AtomicBool>) {}

fn yardim() {
    println!("TR-DPI koruma");
    println!();
    println!("  --ttl <1-255>    sahte paketin yaşam süresi (varsayılan 5)");
    println!("  --kuyruk <no>    NFQUEUE numarası (varsayılan 4200)");
    println!("  --temizle        kalıntı kuralları sil ve çık");
    println!("  --yardim, -h     bu metin");
    println!();
    println!("Yönetici yetkisi gerekir:  sudo trdpi");
}

fn hata(mesaj: &str) {
    eprintln!();
    eprintln!("{mesaj}");
    std::process::exit(1);
}
