//! TLS handshake ölçümü.
//!
//! **Neden hazır bir TLS kütüphanesi kullanmıyoruz:** `rustls`/`native-tls`
//! başarısızlığı tek bir "handshake failed" hatasına indirger. Oysa Türkiye'de
//! gözlenen davranış tam olarak şudur — bağlantı kurulur, ClientHello yazılır,
//! ve *ilk write'tan sonra* sıfırlanır. Bu davranışı sıradan bir zaman
//! aşımından ayırt edebilmek için ClientHello'yu kendimiz yazıp yanıtı ham
//! olarak gözlemliyoruz.
//!
//! Amaç geçerli bir TLS oturumu kurmak değildir; sunucunun *herhangi bir*
//! yanıt vermesi (ServerHello, alert, hatta HelloRetryRequest) trafiğin
//! geçtiğini kanıtlar.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use trdpi_core::Classification;

use crate::tcp::TcpOutcome;

/// TLS ölçümünün sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsOutcome {
    /// Sunucudan TLS kaydı geldi — trafik geçti.
    Responded,
    /// ClientHello yazıldıktan sonra bağlantı sıfırlandı.
    ///
    /// Türkiye'de OONI'nin Discord ölçümlerinde raporlanan davranış budur.
    ResetAfterHello,
    /// ClientHello yazıldı, hiç yanıt gelmedi.
    NoResponse,
    /// Yanıt geldi ama TLS kaydı değil.
    UnexpectedData,
}

impl TlsOutcome {
    /// Bu sonucun işaret ettiği ağ davranışı.
    pub fn classify(self) -> Classification {
        match self {
            Self::Responded => Classification::Healthy,
            Self::ResetAfterHello => Classification::TlsInterference,
            Self::NoResponse => Classification::Timeout,
            Self::UnexpectedData => Classification::TlsInterference,
        }
    }

    /// Handshake'in ilerleyip ilerlemediği.
    pub fn is_success(self) -> bool {
        self == Self::Responded
    }
}

/// SNI alanında verilen isimle bir ClientHello kurar.
///
/// TLS 1.2/1.3 sunucularının yanıt vereceği kadar eksiksizdir; oturum kurmak
/// için değil, yalnızca ölçüm için tasarlanmıştır.
pub fn build_client_hello(sni: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(256);

    body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2

    // random — ölçüm için öngörülebilir olması sorun değil, ama sabit bir
    // desen DPI tarafından imzalanabileceği için zamandan türetiyoruz.
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    for i in 0..32u64 {
        body.push((seed.rotate_left((i % 64) as u32) ^ (i * 0x9E37)) as u8);
    }

    body.push(32); // session_id uzunluğu
    for i in 0..32u64 {
        body.push((seed.rotate_right((i % 64) as u32) ^ (i * 0x7F4A)) as u8);
    }

    let ciphers: [u16; 6] = [
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0xC02F, // ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC030, // ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xC02B, // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    ];
    body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for c in ciphers {
        body.extend_from_slice(&c.to_be_bytes());
    }

    body.extend_from_slice(&[0x01, 0x00]); // compression: yalnızca null

    let mut ext = Vec::with_capacity(128);

    // server_name (0x0000) — ölçümün asıl konusu.
    let host = sni.as_bytes();
    let mut sni_ext = Vec::with_capacity(host.len() + 5);
    sni_ext.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes()); // liste uzunluğu
    sni_ext.push(0x00); // tip: host_name
    sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(host);
    push_extension(&mut ext, 0x0000, &sni_ext);

    // supported_groups (0x000A)
    push_extension(&mut ext, 0x000A, &[0x00, 0x04, 0x00, 0x1D, 0x00, 0x17]);

    // ec_point_formats (0x000B)
    push_extension(&mut ext, 0x000B, &[0x01, 0x00]);

    // signature_algorithms (0x000D)
    push_extension(
        &mut ext,
        0x000D,
        &[0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01],
    );

    // supported_versions (0x002B) — TLS 1.3 ve 1.2
    push_extension(&mut ext, 0x002B, &[0x04, 0x03, 0x04, 0x03, 0x03]);

    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    // Handshake başlığı: tip 0x01 (client_hello) + 3 baytlık uzunluk
    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(0x01);
    let len = body.len();
    handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    handshake.extend_from_slice(&body);

    // Kayıt katmanı: tip 0x16 (handshake), sürüm 0x0301, uzunluk
    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

fn push_extension(out: &mut Vec<u8>, id: u16, data: &[u8]) {
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// Gelen baytların bir TLS kaydı gibi görünüp görünmediği.
///
/// 0x16 handshake, 0x15 alert. Alert de geçerli bir yanıttır: sunucu bizi
/// reddetmiş olabilir ama trafik hedefe ulaşmıştır.
pub fn looks_like_tls_record(buf: &[u8]) -> bool {
    if buf.len() < 3 {
        return false;
    }
    matches!(buf[0], 0x16 | 0x15) && buf[1] == 0x03 && buf[2] <= 0x04
}

/// Kurulmuş bir bağlantı üzerinde TLS handshake'i ölçer.
///
/// Akış: ClientHello yaz → yanıtı bekle → sonucu sınıflandır.
pub fn probe(stream: &mut TcpStream, sni: &str, timeout: Duration) -> (TlsOutcome, Duration) {
    let hello = build_client_hello(sni);
    let started = Instant::now();

    if let Err(e) = stream.set_read_timeout(Some(timeout)) {
        return (classify_io(&e), started.elapsed());
    }
    if let Err(e) = stream.write_all(&hello) {
        return (classify_io(&e), started.elapsed());
    }
    if let Err(e) = stream.flush() {
        return (classify_io(&e), started.elapsed());
    }

    let mut buf = [0u8; 16];
    match stream.read(&mut buf) {
        // Karşı taraf hiçbir şey söylemeden kapattı — müdahaleyle tutarlı.
        Ok(0) => (TlsOutcome::ResetAfterHello, started.elapsed()),
        Ok(n) if looks_like_tls_record(&buf[..n]) => (TlsOutcome::Responded, started.elapsed()),
        Ok(_) => (TlsOutcome::UnexpectedData, started.elapsed()),
        Err(e) => (classify_io(&e), started.elapsed()),
    }
}

fn classify_io(err: &std::io::Error) -> TlsOutcome {
    match TcpOutcome::from_error(err) {
        TcpOutcome::Reset => TlsOutcome::ResetAfterHello,
        TcpOutcome::TimedOut => TlsOutcome::NoResponse,
        _ => TlsOutcome::NoResponse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_kayit_yapisi_dogru() {
        let hello = build_client_hello("ornek.test");

        assert_eq!(hello[0], 0x16, "handshake kaydı");
        assert_eq!(&hello[1..3], &[0x03, 0x01], "kayıt sürümü");

        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(
            record_len,
            hello.len() - 5,
            "kayıt uzunluğu gövdeyle uyumlu"
        );

        assert_eq!(hello[5], 0x01, "client_hello");
        let hs_len = u32::from_be_bytes([0, hello[6], hello[7], hello[8]]) as usize;
        assert_eq!(
            hs_len,
            hello.len() - 9,
            "handshake uzunluğu gövdeyle uyumlu"
        );
    }

    #[test]
    fn sni_pakette_yer_aliyor() {
        let hello = build_client_hello("discord.com");
        let konum = hello.windows(11).position(|w| w == b"discord.com");
        assert!(konum.is_some(), "SNI paketin içinde bulunamadı");
    }

    #[test]
    fn farkli_sni_farkli_uzunluk_veriyor() {
        let kisa = build_client_hello("a.co");
        let uzun = build_client_hello("cok-daha-uzun-bir-alan-adi.test");
        assert_eq!(
            uzun.len() - kisa.len(),
            "cok-daha-uzun-bir-alan-adi.test".len() - "a.co".len()
        );
    }

    #[test]
    fn her_cagri_farkli_random_uretiyor() {
        // Sabit bir desen DPI tarafından imzalanabilir.
        let a = build_client_hello("ornek.test");
        let b = build_client_hello("ornek.test");
        assert_eq!(a.len(), b.len());
        assert_ne!(a, b, "ClientHello sabit görünüyor");
    }

    #[test]
    fn tls_kaydi_taniniyor() {
        assert!(
            looks_like_tls_record(&[0x16, 0x03, 0x03, 0x00]),
            "handshake"
        );
        assert!(looks_like_tls_record(&[0x15, 0x03, 0x01]), "alert");

        assert!(!looks_like_tls_record(&[]));
        assert!(!looks_like_tls_record(&[0x16]));
        assert!(
            !looks_like_tls_record(b"HTTP/1.1 302 Found"),
            "engel sayfası"
        );
        assert!(!looks_like_tls_record(&[0x16, 0x09, 0x09]), "bozuk sürüm");
    }

    /// Denetimin ayırt edilmesini istediği iki durum farklı sınıfa düşmeli.
    #[test]
    fn reset_ve_yanitsizlik_ayri_siniflar() {
        assert_eq!(
            TlsOutcome::ResetAfterHello.classify(),
            Classification::TlsInterference
        );
        assert_eq!(TlsOutcome::NoResponse.classify(), Classification::Timeout);
        assert_eq!(TlsOutcome::Responded.classify(), Classification::Healthy);
    }

    #[test]
    fn alert_yaniti_basarili_sayiliyor() {
        // Sunucu bizi reddetse bile trafik hedefe ulaşmıştır.
        assert!(looks_like_tls_record(&[0x15, 0x03, 0x03]));
        assert!(TlsOutcome::Responded.is_success());
    }
}
