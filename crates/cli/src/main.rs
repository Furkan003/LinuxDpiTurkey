//! TR-DPI — tek komut.
//!
//! ```text
//! sudo trdpi              # ölç, gerekeni düzelt, koru
//! trdpi --olc             # yalnızca ölç (yetki istemez)
//! sudo trdpi --geri       # yapılan her şeyi geri al
//! ```
//!
//! Kullanıcının hangi motorun ne yaptığını bilmesi gerekmiyor; ölçüme göre
//! doğru olanı bu program seçiyor.

mod instance;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use trdpi_core::backend::Backend;
use trdpi_core::profile::{FragmentationMode, Profile};
use trdpi_core::{Mechanism, NetworkFingerprint, SessionId};
use trdpi_diagnostics::recommend::recommend;
use trdpi_diagnostics::{probe_target, Target, Timeouts};
use trdpi_dns::resolver::{self, ResolverConfig, ResolverManager};
use trdpi_dns::{upstream, wire, DEFAULT_CANARY};
use trdpi_transparent::{TransparentConfig, TransparentEngine};

/// Geri alma için önceki adres ayarının saklandığı yer.
const DNS_STATE: &str = "/var/lib/trdpi/onceki-dns";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--yardim" || a == "-h") {
        return yardim();
    }
    if args.iter().any(|a| a == "--durdur") {
        return durdur();
    }
    if args.iter().any(|a| a == "--geri") {
        durdur();
        return geri_al();
    }
    let sadece_olc = args.iter().any(|a| a == "--olc");

    // Süre sınırı: verilen saniyeden sonra kendi kendine geri alır.
    // Bir şeyler ters giderse sistem sonsuza kadar değişmiş kalmaz.
    let mut sure: Option<Duration> = None;
    if let Some(i) = args.iter().position(|a| a == "--sure") {
        match args.get(i + 1).and_then(|v| v.parse::<u64>().ok()) {
            Some(sn) if sn > 0 => sure = Some(Duration::from_secs(sn)),
            _ => return bitir("--sure saniye cinsinden bir sayı bekliyor"),
        }
    }

    // 0. Başka bir kopya çalışıyorsa dinleyici açılamaz ve koruma sessizce
    //    devre dışı kalır. Önce onu durduruyoruz.
    let digerleri = instance::find_others();
    if !digerleri.is_empty() && !sadece_olc {
        println!("Çalışan {} kopya bulundu, durduruluyor...", digerleri.len());
        instance::stop_all(&digerleri);
    }

    // 1. Ölç.
    println!("Ağın ölçülüyor...");
    let sonuclar = olc();
    let oneri = recommend(&sonuclar);
    let parmak_izi = NetworkFingerprint::from_results(&sonuclar);

    println!();
    println!("{}", oneri.summary);

    if sadece_olc {
        println!();
        println!("{}", oneri.reason);
        if !oneri.steps.is_empty() {
            println!();
            for (i, a) in oneri.steps.iter().enumerate() {
                println!("  {}. {a}", i + 1);
            }
        }
        return;
    }

    // 2. Adres çözümlemesi bozuksa önce onu düzelt; yanlış adrese
    //    bağlanılırken başka hiçbir yöntem işe yaramaz.
    if parmak_izi.dns_tampering {
        println!();
        println!("Adres çözümlemesi düzeltiliyor...");
        match dns_duzelt() {
            Ok(kaynak) => println!("  {kaynak} kullanılacak."),
            Err(mesaj) => {
                println!("  {mesaj}");
                println!("  Bu adımsız devam ediliyor.");
            }
        }
    }

    // 3. Koru.
    let mut profile = Profile::baseline();
    profile.name = "Yeniden deneme".into();
    profile.supported_mechanisms = vec![Mechanism::TransparentProxy];
    profile.strategy.fragmentation = FragmentationMode::Off;

    let engine = TransparentEngine::new(TransparentConfig::default());
    let mut snapshot = match engine.prepare(SessionId::new()) {
        Ok(s) => s,
        Err(e) => return bitir(&e.user_message()),
    };
    if let Err(e) = engine.apply(&profile, &mut snapshot) {
        return bitir(&e.user_message());
    }

    println!();
    println!("Koruma aktif. Tüm uygulamalar kapsam içinde.");
    println!("Discord, Sober ve diğerlerinde ayar yapman gerekmiyor.");
    println!();
    println!("Kapsam dışı: UDP trafiği (oyunların gerçek zamanlı bağlantısı).");
    match sure {
        Some(s) => println!("{} saniye sonra kendiliğinden geri alınacak.", s.as_secs()),
        None => println!("Durdurmak için Ctrl+C."),
    }

    let dur = Arc::new(AtomicBool::new(false));
    sinyal_kur(Arc::clone(&dur));

    let basladi = std::time::Instant::now();
    let mut son = std::time::Instant::now();
    while !dur.load(Ordering::SeqCst) {
        if sure.is_some_and(|s| basladi.elapsed() >= s) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
        if son.elapsed() >= Duration::from_secs(20) {
            let s = engine.stats();
            if s.accepted > 0 {
                println!(
                    "  bağlantı: {} · kurulan: {} · yeniden deneme: {}",
                    s.accepted, s.established, s.retries
                );
            }
            son = std::time::Instant::now();
        }
    }

    let s = engine.stats();
    println!();
    println!(
        "Toplam — bağlantı: {} · kurulan: {} · yeniden deneme: {} · başarısız: {}",
        s.accepted, s.established, s.retries, s.failed
    );
    if s.accepted == 0 {
        println!("Hiçbir trafik motora uğramadı; yönlendirme çalışmamış olabilir.");
    }

    println!("Geri alınıyor...");
    match engine.rollback(snapshot) {
        Ok(()) => println!("Temiz."),
        Err(e) => {
            eprintln!("{}", e.user_message());
            eprintln!("Kurtarma:  sudo trdpi --geri");
            std::process::exit(1);
        }
    }
}

/// Çalışan kopyaları durdurur.
fn durdur() {
    let digerleri = instance::find_others();
    if digerleri.is_empty() {
        println!("Çalışan kopya yok.");
        return;
    }
    let n = instance::stop_all(&digerleri);
    println!("{n} kopya durduruldu.");
}

/// Taban ve ölçüm hedeflerini sırayla dener.
fn olc() -> Vec<trdpi_core::DiagnosticResult> {
    let hedefler = [
        Target::baseline("example.com"),
        Target::probe("discord.com"),
        Target::probe("www.roblox.com"),
    ];
    let t = Timeouts::default();
    let mut hepsi = Vec::new();
    for h in &hedefler {
        hepsi.extend(probe_target(h, &t));
    }
    hepsi
}

/// Çalışan bir adres kaynağı bulup sistemi ona yönlendirir.
fn dns_duzelt() -> Result<String, String> {
    let Some((secilen, _)) = upstream::find_working(DEFAULT_CANARY, Duration::from_secs(4)) else {
        return Err("Çalışan bir adres kaynağı bulunamadı.".into());
    };
    if resolver::detect_manager() != ResolverManager::SystemdResolved {
        return Err("Bu sistemde adres ayarı otomatik değiştirilemiyor.".into());
    }
    let Some(arayuz) = resolver::default_interface() else {
        return Err("Ağ bağlantısı bulunamadı.".into());
    };

    // Geri alabilmek için önceki ayarı sakla.
    let onceki = resolver::run(&ResolverConfig::query_command(&arayuz))
        .map(|s| {
            s.split(':')
                .next_back()
                .unwrap_or("")
                .split_whitespace()
                .filter(|t| t.parse::<std::net::IpAddr>().is_ok())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    if let Some(dir) = std::path::Path::new(DNS_STATE).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(DNS_STATE, &onceki);

    let config = ResolverConfig {
        interface: arayuz,
        upstream: secilen.addr,
    };
    resolver::run(&config.apply_command()).map_err(|e| e.user_message().to_string())?;

    // Çalışma anındaki ayar yeniden başlatınca kaybolur; kalıcı da yaz.
    // Başarısız olursa koruma yine çalışır, yalnızca her açılışta
    // komutu tekrarlamak gerekir.
    let kalici = resolver::write_persistent(secilen.addr).is_ok();
    Ok(if kalici {
        format!("{} (yeniden başlatmaya dayanıklı)", secilen.label)
    } else {
        format!("{} (yalnızca bu oturum için)", secilen.label)
    })
}

/// Yapılan her değişikliği geri alır.
fn geri_al() {
    // Yönlendirme kuralları: kalıntı varsa temizle.
    let temizlenen = trdpi_transparent::cleanup::remove_orphans().unwrap_or_default();
    if !temizlenen.is_empty() {
        println!("Yönlendirme kuralları kaldırıldı ({}).", temizlenen.len());
    }

    // Kalıcı ayar dosyası.
    match resolver::remove_persistent() {
        Ok(()) => {}
        Err(e) => eprintln!("{}", e.user_message()),
    }

    // Adres ayarı.
    if let Some(arayuz) = resolver::default_interface() {
        let onceki = std::fs::read_to_string(DNS_STATE).unwrap_or_default();
        match resolver::run(&ResolverConfig::revert_command(onceki.trim(), &arayuz)) {
            Ok(_) => {
                let _ = std::fs::remove_file(DNS_STATE);
                if onceki.trim().is_empty() {
                    println!("Adres ayarı bağlantının varsayılanına döndürüldü.");
                } else {
                    println!("Adres ayarı geri getirildi: {}", onceki.trim());
                }
            }
            Err(e) => eprintln!("{}", e.user_message()),
        }
    }
    println!("Temiz.");
}

/// Sistemin çözümleyicisinin sansür adresi döndürüp döndürmediği.
#[allow(dead_code)]
fn sistem_zehirli() -> bool {
    use std::net::ToSocketAddrs;
    format!("{DEFAULT_CANARY}:443")
        .to_socket_addrs()
        .map(|it| {
            let v: Vec<_> = it
                .filter_map(|a| match a.ip() {
                    std::net::IpAddr::V4(ip) => Some(ip),
                    _ => None,
                })
                .collect();
            wire::is_censorship_response(&wire::DnsAnswer {
                addresses: v,
                rcode: 0,
            })
        })
        .unwrap_or(false)
}

/// Ctrl+C ve kapatma sinyallerini yakalar.
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
    println!("TR-DPI");
    println!();
    println!("  sudo trdpi        ölç, gerekeni düzelt, koru");
    println!("  trdpi --olc       yalnızca ölç (yetki istemez)");
    println!("  sudo trdpi --sure <sn>  belirtilen süre sonunda kendiliğinden geri al");
    println!("  sudo trdpi --durdur     çalışan kopyaları durdur");
    println!("  sudo trdpi --geri yapılan her şeyi geri al");
    println!("  trdpi --yardim    bu metin");
}

fn bitir(mesaj: &str) {
    eprintln!();
    eprintln!("{mesaj}");
    std::process::exit(1);
}
