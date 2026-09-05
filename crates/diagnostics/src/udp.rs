//! UDP ölçümü — QUIC ve gerçek zamanlı trafik.
//!
//! İki ayrı soru soruluyor ve karıştırılmamaları önemli:
//!
//! 1. **QUIC (UDP 443) çalışıyor mu.** Çalışmıyorsa uygulama önce QUIC
//!    deniyor, zaman aşımını bekliyor ve ancak sonra TCP'ye düşüyor.
//!    Kullanıcının gördüğü "yavaşlık" çoğunlukla bu bekleme.
//!
//! 2. **Gerçek zamanlı trafik (yüksek portlar) çalışıyor mu.** Oyunların ve
//!    sesli görüşmenin kullandığı yol bu. Koruma buraya hiç dokunmuyor;
//!    ölçüyoruz ki dokunmadığımızı iddia etmek yerine gösterebilelim.
//!
//! Her iki ölçüm de standart, kendi kendine yeten protokol istekleri
//! kullanıyor; hiçbir yere veri yollanmıyor, yalnızca yanıt gelip gelmediğine
//! bakılıyor.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use trdpi_core::{Classification, DiagnosticKind, DiagnosticResult};

/// Gerçek zamanlı yolun ölçüldüğü sunucular.
///
/// STUN, oyunların ve sesli görüşmenin bağlantı kurarken gerçekten kullandığı
/// protokol. Çalışıyorsa gerçek zamanlı yol açık demektir.
pub const STUN_SERVERS: [&str; 2] = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];

/// QUIC'in sürüm görüşmesi yanıtı vermeye zorlandığı sürüm numarası.
///
/// RFC 9000: sunucu tanımadığı bir sürüm görürse sürüm görüşmesi paketiyle
/// yanıt vermek zorundadır. Böylece TLS kurmadan, tek pakette "UDP 443 açık
/// mı" sorusunun cevabı alınıyor.
const ZORLAMA_SURUMU: [u8; 4] = [0x0a, 0x0a, 0x0a, 0x0a];

/// QUIC istemcisinin ilk datagramı için asgari boy (RFC 9000).
const QUIC_ASGARI: usize = 1200;

/// Sürüm görüşmesini tetikleyen QUIC uzun başlıklı paketi.
///
/// Saf fonksiyon: ağa dokunmaz, böylece biçim testle sabitlenebilir.
pub fn quic_probe_packet(token: [u8; 8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(QUIC_ASGARI);
    // Uzun başlık: en üst bit 1, ikinci bit (sabit bit) 1.
    p.push(0xc0);
    p.extend_from_slice(&ZORLAMA_SURUMU);
    // Hedef ve kaynak bağlantı kimlikleri. Sunucu ikisini de yanıtta
    // yerlerini değiştirerek geri gönderir; eşleşme buradan doğrulanıyor.
    p.push(token.len() as u8);
    p.extend_from_slice(&token);
    p.push(token.len() as u8);
    p.extend_from_slice(&token);
    p.resize(QUIC_ASGARI, 0);
    p
}

/// Gelen paketin, gönderdiğimiz isteğe ait bir sürüm görüşmesi yanıtı olup
/// olmadığı.
///
/// Kimliği doğrulamak şart: engelleyen taraf da paket üretebilir. Sürüm alanı
/// sıfır olmayan ya da kimliğimizi taşımayan bir yanıt bizim ölçümümüz
/// değildir.
pub fn is_version_negotiation(paket: &[u8], token: [u8; 8]) -> bool {
    // 1 bayrak + 4 sürüm + 2 uzunluk baytı + iki kimlik.
    if paket.len() < 7 + 2 * token.len() {
        return false;
    }
    if paket[0] & 0x80 == 0 {
        return false;
    }
    if paket[1..5] != [0, 0, 0, 0] {
        return false;
    }
    // Sunucu kimlikleri yer değiştirerek geri gönderir; ikisi de aynı olduğu
    // için tek karşılaştırma yetiyor.
    let dcid_len = paket[5] as usize;
    if dcid_len != token.len() || paket[6..6 + dcid_len] != token {
        return false;
    }
    let scid_bas = 6 + dcid_len;
    let scid_len = paket[scid_bas] as usize;
    scid_len == token.len()
        && paket.len() >= scid_bas + 1 + scid_len
        && paket[scid_bas + 1..scid_bas + 1 + scid_len] == token
}

/// STUN bağlanma isteği (RFC 5389).
///
/// Saf fonksiyon.
pub fn stun_request(token: [u8; 12]) -> Vec<u8> {
    let mut p = Vec::with_capacity(20);
    p.extend_from_slice(&[0x00, 0x01]); // Binding Request
    p.extend_from_slice(&[0x00, 0x00]); // gövde yok
    p.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]); // sihirli değer
    p.extend_from_slice(&token);
    p
}

/// Gelen paketin bizim STUN isteğimizin yanıtı olup olmadığı.
pub fn is_stun_response(paket: &[u8], token: [u8; 12]) -> bool {
    paket.len() >= 20
        && paket[0..2] == [0x01, 0x01] // Binding Success
        && paket[4..8] == [0x21, 0x12, 0xa4, 0x42]
        && paket[8..20] == token
}

/// Rastgele kimlik.
///
/// Kriptografik güç gerekmiyor; tek amaç aynı anda giden ölçümlerin
/// yanıtlarını karıştırmamak ve yoldan geçen bir paketi kendi yanıtımız
/// sanmamak.
fn token<const N: usize>() -> [u8; N] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut t = [0u8; N];
    let mut x = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15)
        | 1;
    for b in t.iter_mut() {
        // SplitMix64 karıştırması.
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        *b = (z ^ (z >> 31)) as u8;
    }
    t
}

/// Tek bir istek gönderip yanıt bekler.
///
/// Yanıtı doğrulayan kararı çağıran veriyor; böylece protokol ayrıntısı ağ
/// kodundan ayrı kalıyor.
fn sor(
    hedef: &str,
    istek: &[u8],
    timeout: Duration,
    kabul: impl Fn(&[u8]) -> bool,
) -> Option<Duration> {
    let adres = hedef.to_socket_addrs().ok()?.next()?;
    let socket = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    socket.connect(adres).ok()?;

    let baslangic = Instant::now();
    socket.send(istek).ok()?;

    // Yabancı bir paket gelirse ölçümü bitirmiyoruz; süre dolana kadar kendi
    // yanıtımızı beklemeye devam ediyoruz.
    let mut buf = [0u8; 2048];
    while baslangic.elapsed() < timeout {
        let n = socket.recv(&mut buf).ok()?;
        if kabul(&buf[..n]) {
            return Some(baslangic.elapsed());
        }
    }
    None
}

/// QUIC (UDP 443) hedefe ulaşıyor mu.
pub fn quic_reachable(host: &str, timeout: Duration) -> DiagnosticResult {
    let t: [u8; 8] = token();
    let istek = quic_probe_packet(t);

    match sor(&format!("{host}:443"), &istek, timeout, |p| {
        is_version_negotiation(p, t)
    }) {
        Some(sure) => DiagnosticResult::ok(DiagnosticKind::QuicReachability, host, sure)
            .with_detail("QUIC yanıt veriyor"),
        // Timeout değil: TCP çalışırken yalnızca QUIC'in kapalı olması
        // ayrı bir durum ve önerileri de ayrı. Timeout desek "hedefe hiç
        // ulaşılamıyor" dalına düşer ve yanlış şey önerirdik.
        None => DiagnosticResult::failed(
            DiagnosticKind::QuicReachability,
            host,
            Classification::QuicBlocked,
        )
        .with_detail("QUIC yanıtsız — uygulamalar TCP'ye düşene kadar bekler"),
    }
}

/// Gerçek zamanlı yol (oyun ve sesli görüşme) açık mı.
///
/// Sunucular sırayla denenir: biri ulaşılamıyorsa bu, yolun kapalı olduğunu
/// değil o sunucunun cevap vermediğini gösterir.
pub fn realtime_reachable(timeout: Duration) -> DiagnosticResult {
    let mut son = None;
    for sunucu in STUN_SERVERS {
        let t: [u8; 12] = token();
        let istek = stun_request(t);
        if let Some(sure) = sor(sunucu, &istek, timeout, |p| is_stun_response(p, t)) {
            return DiagnosticResult::ok(DiagnosticKind::RealtimeUdp, sunucu, sure)
                .with_detail("gerçek zamanlı yol açık");
        }
        son = Some(sunucu);
    }

    // Gerçek zamanlı yolun kapalı olması ciddi ama teşhisin ana konusu
    // değil; en ciddi bulgu olarak raporlanıp asıl engeli gölgelememeli.
    DiagnosticResult::failed(
        DiagnosticKind::RealtimeUdp,
        son.unwrap_or(STUN_SERVERS[0]),
        Classification::Degraded,
    )
    .with_detail("gerçek zamanlı yol yanıtsız")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_paketi_asgari_boyu_tutturuyor() {
        let p = quic_probe_packet([1; 8]);
        assert_eq!(p.len(), QUIC_ASGARI, "kısa datagram sunucuyu tetiklemez");
        assert_eq!(p[0] & 0xc0, 0xc0, "uzun başlık değil");
        assert_eq!(p[1..5], ZORLAMA_SURUMU);
    }

    #[test]
    fn surum_gorusmesi_taniniyor() {
        let t = [7u8; 8];
        let mut yanit = vec![0x80, 0, 0, 0, 0, 8];
        yanit.extend_from_slice(&t);
        yanit.push(8);
        yanit.extend_from_slice(&t);
        yanit.extend_from_slice(&[0, 0, 0, 1]); // desteklenen sürüm listesi
        assert!(is_version_negotiation(&yanit, t));
    }

    /// Engelleyen taraf da paket üretebilir; kimliği tutmayan yanıt bizim
    /// ölçümümüz sayılmamalı.
    #[test]
    fn yabanci_yanit_sayilmiyor() {
        let t = [7u8; 8];
        let mut yanit = vec![0x80, 0, 0, 0, 0, 8];
        yanit.extend_from_slice(&[9u8; 8]);
        yanit.push(8);
        yanit.extend_from_slice(&[9u8; 8]);
        assert!(!is_version_negotiation(&yanit, t));
    }

    #[test]
    fn kisa_ya_da_bozuk_paket_cokertmiyor() {
        for n in 0..40 {
            let _ = is_version_negotiation(&vec![0xff; n], [1; 8]);
            let _ = is_stun_response(&vec![0xff; n], [1; 12]);
        }
    }

    /// Sürüm alanı sıfır değilse bu bir sürüm görüşmesi değil, sıradan bir
    /// QUIC paketidir.
    #[test]
    fn sifir_olmayan_surum_reddediliyor() {
        let t = [7u8; 8];
        let mut yanit = vec![0x80, 0, 0, 0, 1, 8];
        yanit.extend_from_slice(&t);
        yanit.push(8);
        yanit.extend_from_slice(&t);
        assert!(!is_version_negotiation(&yanit, t));
    }

    #[test]
    fn stun_istegi_bicime_uyuyor() {
        let t = [3u8; 12];
        let p = stun_request(t);
        assert_eq!(p.len(), 20);
        assert_eq!(p[0..2], [0x00, 0x01]);
        assert_eq!(p[4..8], [0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(p[8..20], t);
    }

    #[test]
    fn stun_yaniti_taniniyor() {
        let t = [3u8; 12];
        let mut yanit = vec![0x01, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42];
        yanit.extend_from_slice(&t);
        yanit.extend_from_slice(&[0; 8]);
        assert!(is_stun_response(&yanit, t));

        // Başka bir isteğin yanıtı bize ait değil.
        assert!(!is_stun_response(&yanit, [4u8; 12]));
    }

    /// Kimlikler her çağrıda farklı olmalı; aynı olsalar eşzamanlı ölçümler
    /// birbirinin yanıtını sayardı.
    #[test]
    fn kimlikler_tekrar_etmiyor() {
        let a: [u8; 12] = token();
        let b: [u8; 12] = token();
        assert_ne!(a, b);
        assert!(a.iter().any(|&x| x != 0));
    }
}

/// Ada göre QUIC engelinin ölçüm sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicAdSonucu {
    /// Hem masum hem engelli adla el sıkışma başlıyor: ada göre engel yok.
    Engelsiz,
    /// Masum adla başlıyor, engelli adla başlamıyor. Denetim Initial'ı çözüp
    /// sunucu adını okuyor demektir.
    AdaGoreEngelli,
    /// Masum adla da yanıt gelmedi; sorun QUIC'in kendisinde ya da hedefte.
    /// Bu durumda ada göre engel olup olmadığı **bilinemiyor**.
    Olculemedi,
}

/// Doğrulamada kullanılan, engellenmediği varsayılan ad.
const MASUM: &str = "www.google.com";

/// Verilen sunucu adıyla QUIC el sıkışması başlatılabiliyor mu?
///
/// Geçerli bir Initial gönderip **herhangi bir** yanıt bekliyoruz. Sunucu
/// ServerHello, Retry ya da sürüm pazarlığı dönebilir; hepsi paketin karşıya
/// ulaştığını kanıtlar. El sıkışmayı tamamlamıyoruz, gerek yok.
pub fn quic_sni_ulasiyor(hedef: SocketAddr, sni: &str, timeout: Duration) -> bool {
    let tohum = u64::from_be_bytes(token::<8>());
    let paket = trdpi_core::quic_initial::sahte_initial(sni, tohum);

    let Ok(sock) = UdpSocket::bind(("0.0.0.0", 0)) else {
        return false;
    };
    if sock.set_read_timeout(Some(timeout)).is_err() || sock.send_to(&paket, hedef).is_err() {
        return false;
    }
    let mut yanit = [0u8; 2048];
    sock.recv_from(&mut yanit).is_ok()
}

/// QUIC engelinin **ada göre** olup olmadığını ölçer.
///
/// Aynı adrese aynı porttan iki Initial gönderiliyor; tek değişken sunucu
/// adı. Böylece "QUIC kapalı" ile "bu ad engelli" ayrımı yapılabiliyor —
/// yolun genel açıklığına bakan ölçüm bunu göremiyordu.
pub fn quic_ada_gore_engelli(
    hedef: SocketAddr,
    sni: &str,
    timeout: Duration,
) -> QuicAdSonucu {
    // Önce kontrol: masum adla ulaşılamıyorsa karşılaştıracak bir şey yok.
    if !quic_sni_ulasiyor(hedef, MASUM, timeout) {
        return QuicAdSonucu::Olculemedi;
    }
    if quic_sni_ulasiyor(hedef, sni, timeout) {
        QuicAdSonucu::Engelsiz
    } else {
        QuicAdSonucu::AdaGoreEngelli
    }
}

#[cfg(test)]
mod ad_testleri {
    use super::*;

    #[test]
    fn urettigimiz_paket_gecerli_initial() {
        let p = trdpi_core::quic_initial::sahte_initial("ornek.com", 1);
        assert!(p.len() >= 1200);
        assert_eq!(p[0] & 0xF0, 0xC0);
        assert_eq!(&p[1..5], &[0x00, 0x00, 0x00, 0x01]);
    }

    /// Yanıt vermeyen bir adres zaman aşımına uğramalı, asılı kalmamalı.
    #[test]
    fn yanitsiz_adres_zaman_asimina_ugruyor() {
        let hedef: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let basladi = Instant::now();
        assert!(!quic_sni_ulasiyor(hedef, "ornek.com", Duration::from_millis(300)));
        assert!(basladi.elapsed() < Duration::from_secs(2));
    }

    /// Kontrol başarısızsa sonuç "ölçülemedi" olmalı; yanlış suçlama yapmıyoruz.
    #[test]
    fn kontrol_tutmazsa_olculemedi() {
        let hedef: SocketAddr = "192.0.2.1:443".parse().unwrap();
        assert_eq!(
            quic_ada_gore_engelli(hedef, "ornek.com", Duration::from_millis(200)),
            QuicAdSonucu::Olculemedi
        );
    }
}
