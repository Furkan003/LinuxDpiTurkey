//! Adres çözümleme ayarını düzeltir.
//!
//! ```text
//! trdpi-dns --dene        # yetki istemez, yalnızca arar
//! sudo trdpi-dns          # uygular
//! sudo trdpi-dns --geri   # eski haline döndürür
//! ```

use std::time::Duration;

use trdpi_dns::resolver::{self, ResolverConfig, ResolverError, ResolverManager};
use trdpi_dns::{upstream, wire, DEFAULT_CANARY};

/// Geri alma için önceki ayarın saklandığı yer.
const STATE_FILE: &str = "/var/lib/trdpi/onceki-dns";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--yardim" || a == "-h") {
        return yardim();
    }
    let sadece_dene = args.iter().any(|a| a == "--dene");
    let geri_al = args.iter().any(|a| a == "--geri");

    if geri_al {
        return geri();
    }

    // 1. Sorun gerçekten DNS'te mi?
    println!("Adres çözümleme kontrol ediliyor...");
    let sistem_zehirli = sistem_zehirli_mi();
    match sistem_zehirli {
        Some(true) => println!("  Sistemin verdiği adres sansür adresi. Sorun burada."),
        Some(false) => {
            println!("  Sistemin çözümlemesi temiz görünüyor.");
            println!();
            println!("Adres çözümlemede bir sorun görünmüyor; değiştirmeye gerek yok.");
            if !sadece_dene {
                return;
            }
        }
        None => println!("  Sistemin çözümlemesi okunamadı, yine de devam ediliyor."),
    }

    // 2. Çalışan bir kaynak var mı?
    println!();
    println!("Çalışan bir adres kaynağı aranıyor...");
    let mut bulunan = None;
    for up in upstream::candidates() {
        print!("  {:<34} ", up.label);
        match upstream::probe(&up, DEFAULT_CANARY, Duration::from_secs(4)) {
            upstream::ProbeOutcome::Usable { latency } => {
                println!("çalışıyor ({} ms)", latency.as_millis());
                bulunan = Some(up);
                break;
            }
            upstream::ProbeOutcome::Poisoned => println!("bu da sansürlü"),
            upstream::ProbeOutcome::Unreachable => println!("ulaşılamıyor"),
        }
    }

    let Some(secilen) = bulunan else {
        println!();
        println!("Çalışan bir adres kaynağı bulunamadı.");
        println!("Bu ağda adres çözümlemeyi düzeltmek işe yaramaz; engel başka yerde.");
        std::process::exit(1);
    };

    println!();
    println!("Seçilen kaynak: {} — {}", secilen.label, secilen.addr);

    if sadece_dene {
        println!();
        println!("Deneme kipi: hiçbir şey değiştirilmedi.");
        println!("Uygulamak için:  sudo trdpi-dns");
        return;
    }

    // 3. Uygula.
    if resolver::detect_manager() != ResolverManager::SystemdResolved {
        return bitir(ResolverError::NotFound);
    }
    let Some(arayuz) = resolver::default_interface() else {
        return bitir(ResolverError::NoInterface);
    };

    let onceki = mevcut_ayar(&arayuz);
    if let Err(e) = onceki_kaydet(&onceki) {
        eprintln!("Uyarı: önceki ayar kaydedilemedi ({e}).");
        eprintln!("Geri alma için: sudo trdpi-dns --geri");
    }

    let config = ResolverConfig {
        interface: arayuz.clone(),
        upstream: secilen.addr,
        tls_host: None,
    };
    if let Err(e) = resolver::run(&config.apply_command()) {
        return bitir(e);
    }

    println!();
    println!("Uygulandı. ({arayuz})");
    println!();
    println!("Geri almak için:  sudo trdpi-dns --geri");
    println!("Kontrol için:     ./trdpi-teshis");
}

/// Sistemin çözümleyicisi sansür adresi mi döndürüyor.
fn sistem_zehirli_mi() -> Option<bool> {
    use std::net::ToSocketAddrs;

    let adresler: Vec<_> = format!("{DEFAULT_CANARY}:443")
        .to_socket_addrs()
        .ok()?
        .filter_map(|a| match a.ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            _ => None,
        })
        .collect();

    if adresler.is_empty() {
        return None;
    }
    Some(wire::is_censorship_response(&wire::DnsAnswer {
        addresses: adresler,
        rcode: 0,
    }))
}

#[cfg(target_os = "linux")]
fn mevcut_ayar(arayuz: &str) -> String {
    resolver::run(&ResolverConfig::query_command(arayuz))
        .map(|s| {
            // Biçim: "Link 2 (enp3s0): 192.168.1.1"
            s.split(':')
                .next_back()
                .unwrap_or("")
                .split_whitespace()
                .filter(|t| t.parse::<std::net::IpAddr>().is_ok())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
fn mevcut_ayar(_arayuz: &str) -> String {
    String::new()
}

fn onceki_kaydet(deger: &str) -> std::io::Result<()> {
    if let Some(dir) = std::path::Path::new(STATE_FILE).parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(STATE_FILE, deger)
}

fn geri() {
    let Some(arayuz) = resolver::default_interface() else {
        return bitir(ResolverError::NoInterface);
    };
    let onceki = std::fs::read_to_string(STATE_FILE).unwrap_or_default();

    #[cfg(target_os = "linux")]
    if let Err(e) = resolver::run(&ResolverConfig::revert_command(onceki.trim(), &arayuz)) {
        return bitir(e);
    }

    let _ = std::fs::remove_file(STATE_FILE);
    if onceki.trim().is_empty() {
        println!("Ayar, bağlantının kendi varsayılanına döndürüldü. ({arayuz})");
    } else {
        println!("Önceki ayar geri getirildi: {} ({arayuz})", onceki.trim());
    }
}

fn yardim() {
    println!("TR-DPI adres çözümleme düzeltmesi");
    println!();
    println!("  --dene          yalnızca ara, hiçbir şey değiştirme (yetki istemez)");
    println!("  --geri          önceki ayara dön");
    println!("  --yardim, -h    bu metin");
    println!();
    println!("Uygulamak için yönetici yetkisi gerekir:  sudo trdpi-dns");
}

fn bitir(e: ResolverError) {
    eprintln!();
    eprintln!("{}", e.user_message());
    std::process::exit(1);
}
