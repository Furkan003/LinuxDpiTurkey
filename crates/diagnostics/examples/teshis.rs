//! Teşhis motorunu komut satırından çalıştırır.
//!
//! ```text
//! cargo run -p trdpi-diagnostics --example teshis
//! cargo run -p trdpi-diagnostics --example teshis -- discord.com example.com
//! ```
//!
//! Ayrıcalık gerektirmez ve sistemde hiçbir şeyi değiştirmez.

use std::time::Duration;

use trdpi_core::{Classification, NetworkFingerprint};
use trdpi_diagnostics::{probe_target, Target, Timeouts};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let targets: Vec<Target> = if args.is_empty() {
        vec![
            Target::baseline("example.com"),
            Target::baseline("cloudflare.com"),
            Target::probe("discord.com"),
            Target::probe("www.instagram.com"),
        ]
    } else {
        args.iter().map(|h| Target::probe(h)).collect()
    };

    let timeouts = Timeouts::default();
    let mut all = Vec::new();

    println!("TR-DPI teşhis — {} hedef\n", targets.len());

    for target in &targets {
        let etiket = if target.expect_reachable {
            "taban"
        } else {
            "ölçüm"
        };
        println!("{}  [{}]", target.host, etiket);

        for r in probe_target(target, &timeouts) {
            let isaret = if r.success { "OK  " } else { "HATA" };
            let sure = r
                .latency
                .filter(|d| *d > Duration::ZERO)
                .map(|d| format!("{:>6} ms", d.as_millis()))
                .unwrap_or_else(|| "        -".into());
            let ek = r.detail.as_deref().unwrap_or("");

            println!(
                "  {isaret} {:<16} {sure}  {:<18} {ek}",
                format!("{:?}", r.kind),
                r.classification.as_key()
            );
            all.push(r);
        }
        println!();
    }

    let overall = NetworkFingerprint::overall(&all);
    let fp = NetworkFingerprint::from_results(&all);

    println!("──────────────────────────────────────────────");
    println!("Sonuç: {}", overall.user_message());
    println!("Sınıf: {overall}");

    if !fp.is_clean() {
        let mut sinyaller = Vec::new();
        if fp.dns_tampering {
            sinyaller.push("DNS");
        }
        if fp.tcp_reset {
            sinyaller.push("TCP reset");
        }
        if fp.tls_reset {
            sinyaller.push("TLS müdahale");
        }
        if fp.throttling {
            sinyaller.push("yavaşlatma");
        }
        if fp.quic_blocked {
            sinyaller.push("QUIC");
        }
        println!("Sinyaller: {}", sinyaller.join(", "));
    }

    if overall == Classification::Unknown {
        println!("\nNot: yeterli sinyal toplanamadı — bu 'sorun yok' anlamına gelmez.");
    }
}
