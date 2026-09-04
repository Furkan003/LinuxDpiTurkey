//! Sistem geneli korumayı çalıştırır.
//!
//! ```text
//! sudo trdpi-koruma
//! sudo trdpi-koruma --temizle
//! ```
//!
//! Tüm uygulamalar korunur; hiçbirinde ayar yapılması gerekmez.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use trdpi_core::backend::Backend;
use trdpi_core::profile::{FragmentationMode, Profile};
use trdpi_core::{Mechanism, SessionId};
use trdpi_transparent::{cleanup, TransparentConfig, TransparentEngine};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--yardim" || a == "-h") {
        return yardim();
    }

    // Her açılışta önce yetim kural temizliği. Bu isteğe bağlı değil:
    // önceki çalışma düzgün kapanmadıysa internet şu an kopuk olabilir.
    match cleanup::remove_orphans() {
        Ok(silinen) if !silinen.is_empty() => {
            println!(
                "Önceki çalışmadan kalan {} kural temizlendi.",
                silinen.len()
            );
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("Uyarı: eski kurallar kontrol edilemedi ({e})");
            eprintln!("Yönetici yetkisiyle çalıştırman gerekiyor olabilir.");
        }
    }

    if args.iter().any(|a| a == "--temizle") {
        println!("Temizlik tamamlandı.");
        return;
    }

    let mut port: u16 = 9443;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--port" {
            i += 1;
            match args.get(i).and_then(|v| v.parse().ok()) {
                Some(v) => port = v,
                None => {
                    eprintln!("Hata: --port bir port numarası bekliyor");
                    std::process::exit(2);
                }
            }
        }
        i += 1;
    }

    let mut profile = Profile::baseline();
    profile.name = "Sistem geneli koruma".into();
    profile.supported_mechanisms = vec![Mechanism::TransparentProxy];
    profile.strategy.fragmentation = FragmentationMode::SniAware;

    let engine = TransparentEngine::new(TransparentConfig {
        port,
        ..Default::default()
    });

    let mut snapshot = match engine.prepare(SessionId::new()) {
        Ok(s) => s,
        Err(e) => return bitir(&e.user_message()),
    };

    if let Err(e) = engine.apply(&profile, &mut snapshot) {
        return bitir(&e.user_message());
    }

    println!();
    println!("Koruma aktif. Tüm uygulamalar kapsam içinde.");
    println!("Discord, Sober ve diğerlerinde hiçbir ayar yapman gerekmiyor.");
    println!();
    println!("Kapsam dışı: UDP trafiği (oyunların gerçek zamanlı bağlantısı).");
    println!();
    println!("Durdurmak için Ctrl+C — kurallar otomatik geri alınır.");

    let dur = Arc::new(AtomicBool::new(false));
    sinyal_kur(Arc::clone(&dur));

    while !dur.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
    }

    let sayac = engine.stats();
    println!();
    println!(
        "Bağlantı: {} · kurulan: {} · yeniden deneme: {} · başarısız: {}",
        sayac.accepted, sayac.established, sayac.retries, sayac.failed
    );
    if sayac.accepted == 0 {
        println!("Hiçbir trafik motora uğramadı — yönlendirme çalışmamış olabilir.");
    }
    println!("Kurallar geri alınıyor...");
    match engine.rollback(snapshot) {
        Ok(()) => println!("Temiz. Ağ ayarların eski hâlinde."),
        Err(e) => {
            eprintln!("{}", e.user_message());
            eprintln!();
            eprintln!("Şunu çalıştırarak kurtarabilirsin:  sudo trdpi-koruma --temizle");
            std::process::exit(1);
        }
    }
}

/// Ctrl+C ve `kill` sinyallerini yakalar.
///
/// Bu olmadan süreç kural yerinde dururken ölür ve **tüm TCP trafiği kopar.**
#[cfg(target_os = "linux")]
fn sinyal_kur(dur: Arc<AtomicBool>) {
    use std::sync::OnceLock;
    static BAYRAK: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    let _ = BAYRAK.set(dur);

    extern "C" fn isle(_sig: libc::c_int) {
        if let Some(b) = BAYRAK.get() {
            b.store(true, Ordering::SeqCst);
        }
    }

    // SAFETY: yalnızca atomik bir bayrak yazan, async-signal-safe bir işleyici
    // kuruyoruz.
    unsafe {
        libc::signal(libc::SIGINT, isle as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, isle as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, isle as *const () as libc::sighandler_t);
    }
}

#[cfg(not(target_os = "linux"))]
fn sinyal_kur(_dur: Arc<AtomicBool>) {}

fn yardim() {
    println!("TR-DPI sistem geneli koruma");
    println!();
    println!("  --port <port>   yerel dinleyici portu (varsayılan 9443)");
    println!("  --temizle       kalıntı kuralları sil ve çık");
    println!("  --yardim, -h    bu metin");
    println!();
    println!("Yönetici yetkisi gerekir:  sudo trdpi-koruma");
}

fn bitir(mesaj: &str) {
    eprintln!();
    eprintln!("{mesaj}");
    std::process::exit(1);
}
