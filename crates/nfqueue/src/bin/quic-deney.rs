//! QUIC desync deneyi — **yalnızca ölçüm için**, sürümle dağıtılmıyor.
//!
//! Ölçtüğümüz gerçek: DPI, QUIC Initial paketini çözüp içindeki sunucu adını
//! okuyor ve engelli ada denk gelince datagramı düşürüyor. Aynı IP'ye aynı
//! porttan masum bir adla bağlanmak çalışıyor, engelli adla çalışmıyor.
//!
//! Bu program hangi karşı tekniğin bu hatta işe yaradığını ölçer. Tek bir
//! doğru cevap yok; ağdan ağa değişiyor, o yüzden tahmin etmek yerine
//! deniyoruz.
//!
//! Kullanım:  quic-deney <teknik> <saniye>
//!   gecir            hiçbir şey yapma (taban ölçümü)
//!   parcala:<n>      IP parçalarına böl; ilk parça UDP başlığı + n bayt
//!   sahte:<ttl>      düşük ömürlü bozuk kopya gönder, sonra gerçeği geçir
//!   sahte-parcala:<ttl>:<n>   ikisi birden
//!
//! Kural `bypass` bayrağıyla kurulur: program çökerse paketler düşmez.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const KUYRUK: u16 = 7;
const TABLO: &str = "trdpi_quic_deney";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let teknik = args.first().cloned().unwrap_or_else(|| "gecir".into());
    let saniye: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(60);

    let plan = match Plan::coz(&teknik) {
        Some(p) => p,
        None => {
            eprintln!("bilinmeyen teknik: {teknik}");
            std::process::exit(2);
        }
    };

    if let Err(e) = kurallari_kur() {
        eprintln!("kurallar kurulamadı: {e}");
        std::process::exit(1);
    }
    println!("teknik: {teknik} · süre: {saniye} sn");

    let dur = Arc::new(AtomicBool::new(false));
    let sayac = Arc::new(Sayaclar::default());
    let is = calis(plan, Arc::clone(&dur), Arc::clone(&sayac));

    let basladi = Instant::now();
    while basladi.elapsed() < Duration::from_secs(saniye) {
        std::thread::sleep(Duration::from_millis(200));
    }
    dur.store(true, Ordering::SeqCst);
    if let Some(h) = is {
        let _ = h.join();
    }

    kurallari_kaldir();
    println!(
        "görülen: {} · initial: {} · işlenen: {} · hata: {}",
        sayac.gorulen.load(Ordering::Relaxed),
        sayac.initial.load(Ordering::Relaxed),
        sayac.islenen.load(Ordering::Relaxed),
        sayac.hata.load(Ordering::Relaxed),
    );
}

/// Denenecek teknik.
#[derive(Debug, Clone, Copy)]
enum Plan {
    Gecir,
    Parcala { kesim: usize },
    Sahte { ttl: u8 },
    SahteParcala { ttl: u8, kesim: usize },
}

impl Plan {
    fn coz(s: &str) -> Option<Self> {
        let p: Vec<&str> = s.split(':').collect();
        match p.as_slice() {
            ["gecir"] => Some(Plan::Gecir),
            ["parcala", n] => Some(Plan::Parcala {
                kesim: hizala(n.parse().ok()?),
            }),
            ["sahte", t] => Some(Plan::Sahte { ttl: t.parse().ok()? }),
            ["sahte-parcala", t, n] => Some(Plan::SahteParcala {
                ttl: t.parse().ok()?,
                kesim: hizala(n.parse().ok()?),
            }),
            _ => None,
        }
    }
}

/// IP parça uzaklıkları 8'in katı olmak zorunda.
fn hizala(n: usize) -> usize {
    let n = n.max(8);
    n - (n % 8)
}

#[derive(Default)]
struct Sayaclar {
    gorulen: AtomicU64,
    initial: AtomicU64,
    islenen: AtomicU64,
    hata: AtomicU64,
}

/// Paket bir QUIC Initial mi?
///
/// Uzun başlık biti açık, sabit bit açık, tip alanı Initial (00) ve sürüm 1.
fn quic_initial_mi(udp_yuk: &[u8]) -> bool {
    udp_yuk.len() >= 5 && (udp_yuk[0] & 0xF0) == 0xC0 && udp_yuk[1..5] == [0, 0, 0, 1]
}

/// IPv4 başlığının uzunluğu.
fn ip_basi(buf: &[u8]) -> Option<usize> {
    if buf.len() < 20 || (buf[0] >> 4) != 4 {
        return None;
    }
    let n = ((buf[0] & 0x0F) as usize) * 4;
    (n >= 20 && buf.len() >= n).then_some(n)
}

/// Datagramı iki IP parçasına böler.
///
/// Amaç: DPI parçaları birleştirmiyorsa Initial paketini çözemez, dolayısıyla
/// içindeki sunucu adını da göremez. Sunucu tarafı birleştirmeyi çekirdek
/// düzeyinde zaten yapıyor, yani bağlantı bozulmuyor.
fn parcalara_bol(buf: &[u8], kesim: usize) -> Option<(Vec<u8>, Vec<u8>)> {
    let bas = ip_basi(buf)?;
    let toplam = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if toplam > buf.len() || toplam <= bas {
        return None;
    }
    let yuk = &buf[bas..toplam];
    // İlk parça en az UDP başlığını taşımalı, ikinci parça boş kalmamalı.
    if kesim < 8 || kesim >= yuk.len() {
        return None;
    }

    let mut bir = Vec::with_capacity(bas + kesim);
    bir.extend_from_slice(&buf[..bas]);
    bir.extend_from_slice(&yuk[..kesim]);
    yaz_basligi(&mut bir, bas, 0, true);

    let mut iki = Vec::with_capacity(bas + yuk.len() - kesim);
    iki.extend_from_slice(&buf[..bas]);
    iki.extend_from_slice(&yuk[kesim..]);
    yaz_basligi(&mut iki, bas, (kesim / 8) as u16, false);

    Some((bir, iki))
}

/// Parça başlığındaki uzunluk, bayraklar ve sağlama toplamını düzeltir.
///
/// DF bayrağı temizleniyor: istemci onu kurmuş olabilir, biz parçalıyoruz.
fn yaz_basligi(p: &mut [u8], bas: usize, uzaklik: u16, devam_var: bool) {
    let toplam = p.len() as u16;
    p[2..4].copy_from_slice(&toplam.to_be_bytes());
    let mut bayrak_uzaklik = uzaklik & 0x1FFF;
    if devam_var {
        bayrak_uzaklik |= 0x2000; // MF
    }
    p[6..8].copy_from_slice(&bayrak_uzaklik.to_be_bytes());
    p[10] = 0;
    p[11] = 0;
    let cs = trdpi_nfqueue::packet::checksum(&p[..bas]);
    p[10..12].copy_from_slice(&cs.to_be_bytes());
}

/// Düşük ömürlü, içeriği bozulmuş bir kopya üretir.
///
/// Hedefe ulaşmadan ölmesi için TTL düşük; DPI'nın gördüğü ilk Initial bu
/// olur. İçerik bozulduğu için gerçek bir bağlantı kurmaz.
fn sahte_uret(buf: &[u8], ttl: u8, tohum: u64) -> Option<Vec<u8>> {
    let bas = ip_basi(buf)?;
    let toplam = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if toplam > buf.len() || toplam < bas + 8 + 5 {
        return None;
    }
    let mut p = buf[..toplam].to_vec();
    p[8] = ttl;

    // QUIC yükünün bağlantı kimliğini ve gövdesini değiştiriyoruz; uzunluk
    // aynı kalıyor ki DPI'ya aynı boyda bir Initial görünsün.
    let yuk_bas = bas + 8;
    let mut s = tohum;
    for b in p[yuk_bas + 5..toplam].iter_mut() {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = (s >> 33) as u8;
    }

    // UDP sağlama toplamı: IPv4'te sıfır bırakmak "hesaplanmadı" demektir ve
    // geçerlidir. Bozuk bir toplamla göndermektense sıfırlıyoruz.
    p[bas + 6] = 0;
    p[bas + 7] = 0;

    p[10] = 0;
    p[11] = 0;
    let cs = trdpi_nfqueue::packet::checksum(&p[..bas]);
    p[10..12].copy_from_slice(&cs.to_be_bytes());
    Some(p)
}

#[cfg(target_os = "linux")]
fn calis(
    plan: Plan,
    dur: Arc<AtomicBool>,
    sayac: Arc<Sayaclar>,
) -> Option<std::thread::JoinHandle<()>> {
    use nfq::{Queue, Verdict};

    let gonderici = match trdpi_nfqueue::raw::RawSender::new() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("ham soket açılamadı: {e}");
            return None;
        }
    };
    let mut kuyruk = match Queue::open() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("kuyruk açılamadı: {e}");
            return None;
        }
    };
    if let Err(e) = kuyruk.bind(KUYRUK) {
        eprintln!("kuyruğa bağlanılamadı: {e}");
        return None;
    }
    kuyruk.set_nonblocking(true);

    Some(std::thread::spawn(move || {
        let mut tohum: u64 = 0x9E3779B97F4A7C15;
        while !dur.load(Ordering::SeqCst) {
            let mut msg = match kuyruk.recv() {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(_) => break,
            };
            sayac.gorulen.fetch_add(1, Ordering::Relaxed);

            let buf = msg.get_payload().to_vec();
            let initial = ip_basi(&buf)
                .and_then(|b| buf.get(b + 8..))
                .is_some_and(quic_initial_mi);

            let mut dusur = false;
            if initial {
                sayac.initial.fetch_add(1, Ordering::Relaxed);
                tohum = tohum.wrapping_add(0x9E3779B97F4A7C15);

                let (sahte_ttl, kesim) = match plan {
                    Plan::Gecir => (None, None),
                    Plan::Parcala { kesim } => (None, Some(kesim)),
                    Plan::Sahte { ttl } => (Some(ttl), None),
                    Plan::SahteParcala { ttl, kesim } => (Some(ttl), Some(kesim)),
                };

                if let Some(ttl) = sahte_ttl {
                    match sahte_uret(&buf, ttl, tohum) {
                        Some(s) => {
                            if gonderici.send(&s).is_err() {
                                sayac.hata.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        None => {
                            sayac.hata.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }

                if let Some(k) = kesim {
                    let bolundu = parcalara_bol(&buf, k).is_some_and(|(a, b)| {
                        gonderici.send(&a).is_ok() && gonderici.send(&b).is_ok()
                    });
                    if bolundu {
                        dusur = true; // özgün paket gitmesin, parçalar gitti
                        sayac.islenen.fetch_add(1, Ordering::Relaxed);
                    } else {
                        sayac.hata.fetch_add(1, Ordering::Relaxed);
                    }
                } else if sahte_ttl.is_some() {
                    sayac.islenen.fetch_add(1, Ordering::Relaxed);
                }
            }

            msg.set_verdict(if dusur { Verdict::Drop } else { Verdict::Accept });
            let _ = kuyruk.verdict(msg);
        }
    }))
}

#[cfg(not(target_os = "linux"))]
fn calis(
    _plan: Plan,
    _dur: Arc<AtomicBool>,
    _sayac: Arc<Sayaclar>,
) -> Option<std::thread::JoinHandle<()>> {
    None
}

fn nft(args: &[&str]) -> std::io::Result<bool> {
    let out = std::process::Command::new("nft").args(args).output()?;
    Ok(out.status.success())
}

fn kurallari_kur() -> std::io::Result<()> {
    let _ = nft(&["delete", "table", "inet", TABLO]);
    let mark = trdpi_nfqueue::nft::PACKET_MARK.to_string();
    let kuyruk = KUYRUK.to_string();
    let komutlar: Vec<Vec<&str>> = vec![
        vec!["add", "table", "inet", TABLO],
        vec![
            "add",
            "chain",
            "inet",
            TABLO,
            "output",
            "{ type filter hook output priority 0 ; policy accept ; }",
        ],
        vec!["add", "rule", "inet", TABLO, "output", "meta", "mark", &mark, "return"],
        vec![
            "add", "rule", "inet", TABLO, "output", "meta", "nfproto", "ipv4", "udp", "dport",
            "443", "queue", "flags", "bypass", "to", &kuyruk,
        ],
    ];
    for k in komutlar {
        if !nft(&k)? {
            return Err(std::io::Error::other(format!("nft başarısız: {k:?}")));
        }
    }
    Ok(())
}

fn kurallari_kaldir() {
    let _ = nft(&["delete", "table", "inet", TABLO]);
}
