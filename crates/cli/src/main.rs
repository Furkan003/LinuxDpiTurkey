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
use trdpi_core::profile::{FragmentationMode, Profile, QuicMode};
use trdpi_core::{Mechanism, NetworkFingerprint, RiskLevel, SessionId};
use trdpi_diagnostics::recommend::recommend;
use trdpi_diagnostics::{probe_target, udp, Target, Timeouts};
use trdpi_dns::resolver::{self, ResolverConfig, ResolverManager};
use trdpi_dns::{upstream, wire, DEFAULT_CANARY};
use trdpi_transparent::{TransparentConfig, TransparentEngine};

/// Geri alma için önceki adres ayarının saklandığı yer.
const DNS_STATE: &str = "/var/lib/trdpi/onceki-dns";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Yazım hatası olan bir bayrak sessizce yok sayılırsa program varsayılan
    // işini yapar — yani sistem geneli değişiklik uygular. `trdpi --surum`
    // yazan biri sürümü öğrenmek isterken korumayı başlatmamalı.
    if let Some(bilinmeyen) = bilinmeyen_secenek(&args) {
        return bitir(&format!(
            "Bilinmeyen seçenek: {bilinmeyen}
Seçenekler için:  trdpi --yardim"
        ));
    }

    if args.iter().any(|a| a == "--surum" || a == "-V") {
        println!("TR-DPI {}", env!("CARGO_PKG_VERSION"));
        return;
    }
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
    // QUIC koruma kapsamına girmiyor: paket düzeyinde iş ve kullanıcı
    // alanından yapılamıyor. Açık bırakırsak uygulama önce QUIC deniyor,
    // engelleniyor, zaman aşımını bekliyor ve ancak sonra TCP'ye düşüyor —
    // kullanıcının gördüğü "yavaşlık" ve Discord'un açılmaması bu.
    // Reddedip anında TCP'ye düşürüyoruz. İstemeyen kapatabilsin.
    let quic_gecir = args.iter().any(|a| a == "--quic-gecir");

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
    println!("{}", udp_ozeti(&sonuclar));

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

    // 3. QUIC. Önce gerçek çözüm denenir.
    //
    // Ölçtük: DPI, QUIC Initial paketini çözüp içindeki sunucu adını okuyor.
    // Aynı IP'ye masum bir adla bağlanmak çalışıyor, engelli adla
    // çalışmıyor. Gerçek paketten önce gönderilen düşük ömürlü sahte bir
    // Initial bunu aşıyor (18/18 deneme). Kurulamazsa eski davranışa
    // düşüyoruz: QUIC'i kapatıp uygulamaları korunan TCP yoluna almak.
    let nfq = trdpi_nfqueue::NfqueueEngine::new(trdpi_nfqueue::NfqueueConfig::default());
    let mut quic_snapshot = None;
    if !quic_gecir {
        match quic_desync_kur(&nfq) {
            Ok(s) => quic_snapshot = Some(s),
            Err(e) => eprintln!("  QUIC desync kurulamadı ({e}); QUIC kapatılacak."),
        }
    }

    // 4. Koru.
    let mut profile = Profile::baseline();
    profile.name = "Yeniden deneme".into();
    profile.supported_mechanisms = vec![Mechanism::TransparentProxy];
    profile.strategy.fragmentation = FragmentationMode::Off;
    if !quic_gecir && quic_snapshot.is_none() {
        profile.protocols.quic = QuicMode::Block;
        // QUIC'i kapatmak kullanıcının görebileceği bir davranış değişikliği;
        // profil bunu düşük riskli diye etiketleyemez.
        profile.risk = RiskLevel::High;
    }
    if let Err(e) = profile.validate() {
        return bitir(&format!("profil geçersiz: {e}"));
    }

    let engine = TransparentEngine::new(TransparentConfig::default());
    let mut snapshot = match engine.prepare(SessionId::new()) {
        Ok(s) => s,
        Err(e) => {
            // Adres ayarını değiştirmiş olabiliriz; koruma kurulmadıysa
            // kullanıcıyı yarım bir durumda bırakmıyoruz.
            quic_geri_al(&nfq, quic_snapshot);
            dns_geri_al();
            return bitir(&e.user_message());
        }
    };
    if let Err(e) = engine.apply(&profile, &mut snapshot) {
        let _ = engine.rollback(snapshot);
        quic_geri_al(&nfq, quic_snapshot);
        dns_geri_al();
        return bitir(&e.user_message());
    }

    // Koruma gerçekten kurulduktan sonra: arayüz buna bakıyor.
    instance::write_pidfile();

    println!();
    println!("Koruma aktif. Tüm uygulamalar kapsam içinde.");
    println!("Discord, Sober ve diğerlerinde ayar yapman gerekmiyor.");
    println!();
    if quic_gecir {
        println!("QUIC açık bırakıldı (--quic-gecir).");
    } else if quic_snapshot.is_some() {
        println!("QUIC engeli aşılıyor; uygulamalar hızlı yolu kullanmaya devam ediyor.");
    } else {
        println!("QUIC (UDP 443) kapatıldı; uygulamalar korunan TCP yolunu kullanıyor.");
    }
    println!("Oyunların gerçek zamanlı bağlantısına dokunulmuyor.");
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
    if let Some(q) = quic_ozeti(&nfq) {
        println!("{q}");
    }
    if s.alternates > 0 {
        println!(
            "{} bağlantı, özgün adres çalışmadığı için başka bir adresten kuruldu.",
            s.alternates
        );
    }
    if s.accepted == 0 {
        println!("Hiçbir trafik motora uğramadı; yönlendirme çalışmamış olabilir.");
    }

    println!("Geri alınıyor...");
    instance::clear_pidfile();
    // Sıra önemli: önce yönlendirme, sonra adres ayarı. Yönlendirme
    // kalkmadan çözümleyiciyi değiştirirsek arada bir an yanlış adrese
    // giden trafik oluşur.
    let yonlendirme = engine.rollback(snapshot);
    quic_geri_al(&nfq, quic_snapshot);
    dns_geri_al();
    match yonlendirme {
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

    // UDP iki ayrı soru: QUIC (443) ve gerçek zamanlı yol (yüksek portlar).
    // İkisi bağımsız — biri kapalıyken diğeri açık olabilir.
    hepsi.push(udp::quic_reachable("example.com", Duration::from_secs(3)));
    hepsi.push(udp::realtime_reachable(Duration::from_secs(3)));
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

    // Önbellekte sansür adresi kalmasın; kalırsa yeni çözümleyici hiçbir işe
    // yaramaz. Başarısız olursa koruma yine çalışır, yalnızca ilk birkaç
    // istek eski yanıtı görebilir.
    let _ = resolver::run(&ResolverConfig::flush_command());

    // Çalışma anındaki ayar yeniden başlatınca kaybolur; kalıcı da yaz.
    // Başarısız olursa koruma yine çalışır, yalnızca her açılışta
    // komutu tekrarlamak gerekir.
    let kalici = resolver::write_persistent(&config.interface, secilen.addr).is_ok();
    Ok(if kalici {
        format!("{} (yeniden başlatmaya dayanıklı)", secilen.label)
    } else {
        format!("{} (yalnızca bu oturum için)", secilen.label)
    })
}

/// Yapılan her değişikliği geri alır.
fn geri_al() {
    // Kimlik dosyası: sahibi ölmüşse kalmış olabilir.
    temiz_kimlik_dosyasi();

    // Yönlendirme kuralları: kalıntı varsa temizle.
    let temizlenen = trdpi_transparent::cleanup::remove_orphans().unwrap_or_default();
    if !temizlenen.is_empty() {
        println!("Yönlendirme kuralları kaldırıldı ({}).", temizlenen.len());
    }

    dns_geri_al();
    println!("Temiz.");
}

/// QUIC motorunun ne iş yaptığının tek satırlık özeti.
///
/// Hiç Initial görmediyse satır basılmıyor: kullanıcıya "0 paket" demenin
/// bir faydası yok.
fn quic_ozeti(nfq: &trdpi_nfqueue::NfqueueEngine) -> Option<String> {
    let s = nfq.stats();
    (s.quic_seen > 0).then(|| {
        format!(
            "QUIC — görülen bağlantı: {} · engeli aşılan: {}",
            s.quic_seen, s.quic_faked
        )
    })
}

/// QUIC engelini aşan motoru kurar.
///
/// TCP tarafına dokunmuyor: sahte paket tekniği TCP için bu hatta ölçüldü ve
/// işe yaramadı. QUIC için yaradı; motoru yalnızca onun için çalıştırıyoruz.
fn quic_desync_kur(
    nfq: &trdpi_nfqueue::NfqueueEngine,
) -> Result<trdpi_core::backend::Snapshot, String> {
    use trdpi_core::profile::TtlMode;

    let mut p = Profile::baseline();
    p.name = "QUIC desync".into();
    p.supported_mechanisms = vec![Mechanism::Nfqueue];
    p.strategy.fragmentation = FragmentationMode::Off;
    p.strategy.ttl = TtlMode::Off;
    p.protocols.quic = QuicMode::Desync;
    p.validate().map_err(|e| e.to_string())?;

    let mut snapshot = nfq
        .prepare(SessionId::new())
        .map_err(|e| e.user_message().to_string())?;
    nfq.apply(&p, &mut snapshot)
        .map_err(|e| e.user_message().to_string())?;
    Ok(snapshot)
}

/// QUIC motorunu durdurur; kurulmamışsa hiçbir şey yapmaz.
fn quic_geri_al(
    nfq: &trdpi_nfqueue::NfqueueEngine,
    snapshot: Option<trdpi_core::backend::Snapshot>,
) {
    if let Some(s) = snapshot {
        if let Err(e) = nfq.rollback(s) {
            eprintln!("QUIC kuralları kaldırılamadı: {}", e.user_message());
            eprintln!("Kurtarma:  sudo trdpi --geri");
        }
    }
}

/// Adres çözümleme ayarını eski haline getirir.
///
/// Koruma **nasıl biterse bitsin** çağrılmalı: Ctrl+C, sürenin dolması ya da
/// `--durdur`. Çağrılmazsa kullanıcının sistemi yabancı bir çözümleyicide
/// kalır ve kalıcı dosya yeniden başlatmaya da dayandığı için bu sessizce
/// süreklileşir.
///
/// Hiçbir şey değiştirmediysek dokunmuyoruz: kullanıcının kendi elle
/// ayarladığı çözümleyiciyi sıfırlamak, düzeltmekten daha kötü olurdu.
/// Değiştirdiğimizin tek kanıtı durum dosyası ve kalıcı ayar dosyası.
fn dns_geri_al() {
    let durum_var = std::path::Path::new(DNS_STATE).exists();
    // Hem yeni birim hem de eski sürümlerden kalan drop-in dosyası.
    let kalici_var = std::path::Path::new(resolver::UNIT_PATH).exists()
        || std::path::Path::new(resolver::DROPIN_PATH).exists();
    if !durum_var && !kalici_var {
        return;
    }

    if kalici_var {
        if let Err(e) = resolver::remove_persistent() {
            eprintln!("{}", e.user_message());
        }
    }

    let Some(arayuz) = resolver::default_interface() else {
        return;
    };
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

/// UDP ölçümlerinin tek satırlık özeti.
///
/// İki yol ayrı ayrı söyleniyor: kullanıcı "oyunum çalışacak mı" sorusunun
/// cevabını QUIC'ten değil buradan alıyor.
///
/// **Ne ölçmüyor:** buradaki QUIC ölçümü yolun genel olarak açık olup
/// olmadığına bakar. Bu hatta ölçtüğümüz engel ise ada göre çalışıyor — DPI,
/// Initial paketini çözüp sunucu adını okuyor ve yalnızca engelli adlarda
/// datagramı düşürüyor. Yani burada "açık" yazması, engelli bir sitenin QUIC
/// üzerinden açılacağı anlamına gelmez. O engeli koruma açıkken aşıyoruz.
fn udp_ozeti(sonuclar: &[trdpi_core::DiagnosticResult]) -> String {
    use trdpi_core::DiagnosticKind;

    let durum = |kind: DiagnosticKind| {
        sonuclar
            .iter()
            .find(|r| r.kind == kind)
            .map(|r| if r.success { "açık" } else { "kapalı" })
            .unwrap_or("ölçülmedi")
    };

    format!(
        "QUIC (UDP 443) yolu: {} · Gerçek zamanlı yol (oyun, sesli görüşme): {}",
        durum(DiagnosticKind::QuicReachability),
        durum(DiagnosticKind::RealtimeUdp),
    )
}

/// Sahibi ölmüş kimlik dosyasını siler.
///
/// `kill -9` ile ölen bir kopya dosyayı arkasında bırakır; temizlenmezse
/// arayüz sonsuza kadar "çalışıyor" gösterir.
fn temiz_kimlik_dosyasi() {
    for yol in [
        trdpi_core::paths::PIDFILE,
        trdpi_core::paths::PIDFILE_FALLBACK,
    ] {
        let _ = std::fs::remove_file(yol);
    }
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
    println!("  sudo trdpi --quic-gecir  QUIC'i kapatma (bazı siteler hızlanır,");
    println!("                           bazı uygulamalar açılmayabilir)");
    println!("  trdpi --yardim    bu metin");
    println!("  trdpi --surum     sürüm numarası");
}

/// Tanıdığımız bütün seçenekler.
const SECENEKLER: [&str; 9] = [
    "--yardim",
    "-h",
    "--surum",
    "-V",
    "--olc",
    "--durdur",
    "--geri",
    "--quic-gecir",
    "--sure",
];

/// Listede olmayan ilk argümanı döndürür.
///
/// `--sure`'nin ardından bir sayı gelir; o değer seçenek değildir ve
/// atlanır. Saf fonksiyon — testi kolay olsun diye ayrıldı.
fn bilinmeyen_secenek(args: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--sure" {
            i += 2; // seçeneğin kendisi ve değeri
            continue;
        }
        if !SECENEKLER.contains(&a) {
            return Some(a);
        }
        i += 1;
    }
    None
}

fn bitir(mesaj: &str) {
    eprintln!();
    eprintln!("{mesaj}");
    std::process::exit(1);
}

#[cfg(test)]
mod testler {
    use super::*;

    fn v(parcalar: &[&str]) -> Vec<String> {
        parcalar.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn tanidik_secenekler_kabul_ediliyor() {
        assert_eq!(bilinmeyen_secenek(&v(&["--olc"])), None);
        assert_eq!(bilinmeyen_secenek(&v(&["--geri"])), None);
        assert_eq!(bilinmeyen_secenek(&v(&["--quic-gecir", "--surum"])), None);
    }

    #[test]
    fn surenin_degeri_secenek_sayilmiyor() {
        assert_eq!(bilinmeyen_secenek(&v(&["--sure", "120"])), None);
        assert_eq!(bilinmeyen_secenek(&v(&["--sure", "120", "--olc"])), None);
    }

    #[test]
    fn yazim_hatasi_yakalaniyor() {
        // Asıl mesele bu: sessizce yok sayılırsa koruma başlıyordu.
        assert_eq!(bilinmeyen_secenek(&v(&["--surumm"])), Some("--surumm"));
        assert_eq!(bilinmeyen_secenek(&v(&["--version"])), Some("--version"));
        assert_eq!(bilinmeyen_secenek(&v(&["--olc", "--dur"])), Some("--dur"));
    }

    #[test]
    fn bossa_sorun_yok() {
        assert_eq!(bilinmeyen_secenek(&[]), None);
    }
}
