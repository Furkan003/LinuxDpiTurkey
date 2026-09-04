//! # trdpi-diagnostics
//!
//! Ağ ölçüm katmanı. **Hiçbir ayrıcalık gerektirmez** ve sistemde hiçbir şeyi
//! değiştirmez — yalnızca ölçer.
//!
//! Bu, ürünün en değerli parçasıdır: hangi profilin uygulanacağına karar veren
//! sinyal buradan gelir. Paket motorundan bağımsız olarak tek başına da
//! çalışabilir.
//!
//! ## Gizlilik
//!
//! Ölçüm hedefleri sabittir ve kullanıcının gezinme geçmişinden türetilmez.
//! Sonuçlarda trafik içeriği, payload veya tam URL saklanmaz. Ölçümün kendisi
//! ağ üzerinde gözlemlenebilir bir iz bırakır; bu yüzden hedef listesi kısa
//! tutulur ve arka planda sürekli çalıştırılmaz.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod dns;
pub mod recommend;
pub mod tcp;
pub mod tls;

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use trdpi_core::{Classification, DiagnosticKind, DiagnosticResult};

/// Ölçüm zaman aşımları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// DNS sorgusu için.
    pub dns: Duration,
    /// TCP bağlantısı için.
    pub tcp: Duration,
    /// TLS yanıtı için.
    pub tls: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(3),
            tcp: Duration::from_secs(5),
            tls: Duration::from_secs(5),
        }
    }
}

/// Ölçülecek bir hedef.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Alan adı — SNI'da da bu kullanılır.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Bu hedefin engellenmesi beklenmiyor mu.
    ///
    /// `true` olan hedefler taban ölçüm içindir: bunlar da başarısızsa sorun
    /// sansür değil, bağlantının kendisidir.
    pub expect_reachable: bool,
}

impl Target {
    /// Engellenmesi beklenmeyen bir taban hedefi.
    pub fn baseline(host: &str) -> Self {
        Self {
            host: host.to_owned(),
            port: 443,
            expect_reachable: true,
        }
    }

    /// Engellenmiş olabilecek bir hedef.
    pub fn probe(host: &str) -> Self {
        Self {
            host: host.to_owned(),
            port: 443,
            expect_reachable: false,
        }
    }

    /// `host:port` biçimi.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Sistem çözümleyicisiyle adres çözer.
fn resolve(target: &Target) -> std::io::Result<Vec<SocketAddr>> {
    Ok(target.authority().to_socket_addrs()?.collect())
}

/// Karşılaştırma için sorulan bağımsız çözümleyiciler.
///
/// İlki standart portta; müdahale bu portta yapılıyorsa o da zehirli yanıt
/// döner. İkincisi **standart dışı portta**, çünkü 53. porttaki yönlendirme
/// onu yakalamaz. İkisinin farklı cevap vermesi, müdahalenin nerede
/// olduğunu söyler.
const REFERENCE_RESOLVERS: [(&str, &str); 2] = [
    ("1.1.1.1:53", "standart port"),
    ("77.88.8.8:1253", "standart dışı port"),
];

/// Sistem çözümleyicisinin yanıtını bağımsız çözümleyicilerle karşılaştırır.
///
/// Yalnızca "adresler farklı" demek yetmez: CDN'ler bölgeye göre zaten farklı
/// adres döndürür ve bunu müdahale saymak yanlış olur. Bu yüzden fark
/// bulununca **ikisine de bağlanmayı deniyoruz**. Sistemin verdiği adrese
/// ulaşılamıyor ama bağımsız kaynağınkine ulaşılıyorsa, zehirlenme kanıtlanmış
/// olur; ikisi de çalışıyorsa bu sadece CDN farkıdır.
fn check_dns(target: &Target, timeouts: &Timeouts, system: &[SocketAddr]) -> DiagnosticResult {
    use std::net::IpAddr;

    let sistem: Vec<Ipv4Addr> = system
        .iter()
        .filter_map(|a| match a.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect();

    let sistem_yanit = dns::DnsAnswer {
        addresses: sistem.clone(),
        rcode: 0,
    };

    let tampered = |detay: String| {
        DiagnosticResult::failed(
            DiagnosticKind::DnsIntegrity,
            &target.host,
            Classification::DnsTampered,
        )
        .with_detail(detay)
    };

    // Bilinen sansür adresi tek başına kesin kanıttır.
    if dns::is_censorship_response(&sistem_yanit) {
        return tampered("bilinen sansür adresi döndü".into());
    }

    let mut sorulabilen = 0;
    let mut farkli: Option<(Ipv4Addr, &str)> = None;

    for (adres, etiket) in REFERENCE_RESOLVERS {
        let Ok(resolver) = adres.parse() else {
            continue;
        };
        let Ok(yanit) = dns::query(resolver, &target.host, timeouts.dns) else {
            continue;
        };
        sorulabilen += 1;

        if dns::is_censorship_response(&yanit) {
            return tampered(format!("{etiket}: bilinen sansür adresi"));
        }
        if farkli.is_none() && dns::answers_disagree(&sistem_yanit, &yanit) {
            if let Some(ip) = yanit.addresses.first() {
                farkli = Some((*ip, etiket));
            }
        }
    }

    if sorulabilen == 0 {
        // Karşılaştırma yapılamadı; "sorun yok" demek yanlış olur.
        return DiagnosticResult::failed(
            DiagnosticKind::DnsIntegrity,
            &target.host,
            Classification::Unknown,
        )
        .with_detail("bağımsız çözümleyiciye ulaşılamadı".to_string());
    }

    let Some((bagimsiz_ip, etiket)) = farkli else {
        return DiagnosticResult::ok(DiagnosticKind::DnsIntegrity, &target.host, Duration::ZERO)
            .with_detail(format!(
                "{} adres, {sorulabilen} kaynakla doğrulandı",
                sistem.len()
            ));
    };

    // Adresler farklı. Fark tek başına bir şey söylemez — hangisinin
    // çalıştığına bakalım.
    let Some(sistem_ip) = sistem.first() else {
        return tampered(format!("{etiket} adres verdi, sistem vermedi"));
    };

    let sistem_calisiyor = tcp::connect(
        SocketAddr::new(IpAddr::V4(*sistem_ip), target.port),
        timeouts.tcp,
    )
    .0
    .is_success();

    let bagimsiz_calisiyor = tcp::connect(
        SocketAddr::new(IpAddr::V4(bagimsiz_ip), target.port),
        timeouts.tcp,
    )
    .0
    .is_success();

    match (sistem_calisiyor, bagimsiz_calisiyor) {
        // Kanıt: sistemin verdiği adres ölü, bağımsız kaynağınki canlı.
        (false, true) => tampered(format!(
            "sistemin verdiği {sistem_ip} ulaşılamıyor, {etiket} adresi {bagimsiz_ip} çalışıyor"
        )),
        // İkisi de çalışıyor: bu yalnızca CDN farkı.
        (true, _) => {
            DiagnosticResult::ok(DiagnosticKind::DnsIntegrity, &target.host, Duration::ZERO)
                .with_detail(format!("{} adres, farklar CDN kaynaklı", sistem.len()))
        }
        // İkisi de ölü: sorun DNS'te değil.
        (false, false) => {
            DiagnosticResult::ok(DiagnosticKind::DnsIntegrity, &target.host, Duration::ZERO)
                .with_detail("adresler farklı ama hiçbiri çalışmıyor — sorun DNS değil".to_string())
        }
    }
}

/// Adresin ayakta olup olmadığını anlamak için denenen ikinci port.
///
/// Şifresiz web portu neredeyse her sunucuda açıktır; kapalıysa sorun büyük
/// ihtimalle adresin kendisindedir.
pub const CROSS_CHECK_PORT: u16 = 80;

/// Aynı adrese ikinci bir porttan bağlanmayı dener.
///
/// `Some(true)`: adres ayakta, engel hedef porta özel.
/// `Some(false)`: adrese hiçbir kapıdan ulaşılamıyor.
/// `None`: sonuç yorumlanamıyor (bağlantı açıkça reddedildi — sunucu orada
/// ama o portu dinlemiyor olabilir).
fn cross_check_port(addr: SocketAddr, timeout: Duration) -> Option<bool> {
    if addr.port() == CROSS_CHECK_PORT {
        return None;
    }
    let ikinci = SocketAddr::new(addr.ip(), CROSS_CHECK_PORT);
    match tcp::connect(ikinci, timeout).0 {
        tcp::TcpOutcome::Connected => Some(true),
        tcp::TcpOutcome::TimedOut => Some(false),
        // Reddedilme "port kapalı" demektir, adres hakkında bir şey söylemez.
        _ => None,
    }
}

/// Tek bir hedef için DNS → TCP → TLS zincirini çalıştırır.
///
/// Zincir kısa devre yapar: TCP kurulamazsa TLS ölçülmez, çünkü o aşamada
/// TLS hakkında söylenebilecek hiçbir şey yoktur.
pub fn probe_target(target: &Target, timeouts: &Timeouts) -> Vec<DiagnosticResult> {
    let mut results = Vec::with_capacity(3);

    let addrs = match resolve(target) {
        Ok(a) if !a.is_empty() => {
            results.push(check_dns(target, timeouts, &a));
            a
        }
        _ => {
            results.push(DiagnosticResult::failed(
                DiagnosticKind::DnsIntegrity,
                &target.host,
                Classification::DnsTampered,
            ));
            return results;
        }
    };

    let addr = addrs[0];
    let (tcp_outcome, tcp_time, stream) = tcp::connect(addr, timeouts.tcp);

    results.push(if tcp_outcome.is_success() {
        DiagnosticResult::ok(DiagnosticKind::TcpConnect, target.authority(), tcp_time)
    } else {
        // Bağlantı kurulamadı. Adresin tamamen ulaşılamaz olması ile yalnızca
        // bu portun engellenmesi farklı şeylerdir ve farklı çözüm gerektirir,
        // bu yüzden aynı adrese başka bir porttan da bakıyoruz.
        let detay = match cross_check_port(addr, timeouts.tcp) {
            Some(true) => format!(
                "{tcp_outcome:?} — adres ayakta ({} kapısı açılıyor), engel bu kapıya özel",
                CROSS_CHECK_PORT
            ),
            Some(false) => format!("{tcp_outcome:?} — adrese hiçbir kapıdan ulaşılamıyor"),
            None => format!("{tcp_outcome:?}"),
        };
        DiagnosticResult::failed(
            DiagnosticKind::TcpConnect,
            target.authority(),
            tcp_outcome.classify(),
        )
        .with_detail(detay)
    });

    let Some(mut stream) = stream else {
        return results;
    };

    let (tls_outcome, tls_time) = tls::probe(&mut stream, &target.host, timeouts.tls);
    results.push(if tls_outcome.is_success() {
        DiagnosticResult::ok(DiagnosticKind::TlsHandshake, &target.host, tls_time)
    } else {
        DiagnosticResult::failed(
            DiagnosticKind::TlsHandshake,
            &target.host,
            tls_outcome.classify(),
        )
        .with_detail(format!("{tls_outcome:?}"))
    });

    results
}

/// Taban ölçümün, sansürden bağımsız olarak bağlantının çalıştığını
/// gösterip göstermediği.
///
/// `expect_reachable` hedefleri de başarısızsa sonuçları sansür olarak
/// yorumlamak yanlıştır — internet bağlantısının kendisi kopuk olabilir.
pub fn baseline_is_sound(targets: &[Target], results: &[(usize, Vec<DiagnosticResult>)]) -> bool {
    let mut baseline_seen = false;
    for (idx, rs) in results {
        let Some(t) = targets.get(*idx) else { continue };
        if !t.expect_reachable {
            continue;
        }
        baseline_seen = true;
        if rs.iter().all(|r| r.success) {
            return true;
        }
    }
    !baseline_seen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hedef_biciminde_port_var() {
        assert_eq!(Target::baseline("ornek.test").authority(), "ornek.test:443");
        assert!(Target::baseline("a.test").expect_reachable);
        assert!(!Target::probe("a.test").expect_reachable);
    }

    #[test]
    fn cozumlenemeyen_hedef_zinciri_kesiyor() {
        let target = Target::probe("bu-alan-adi-yok.invalid");
        let results = probe_target(&target, &Timeouts::default());

        // Yalnızca DNS sonucu üretilmeli; TCP/TLS denenmemiş olmalı.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, DiagnosticKind::DnsIntegrity);
        assert!(!results[0].success);
    }

    #[test]
    fn baglanamayan_hedefte_tls_olculmuyor() {
        // Kapalı yerel port: DNS çözülür, TCP başarısız, TLS denenmez.
        let target = Target {
            host: "127.0.0.1".into(),
            port: 1,
            expect_reachable: false,
        };
        let results = probe_target(&target, &Timeouts::default());

        assert_eq!(results.len(), 2);
        assert_eq!(results[1].kind, DiagnosticKind::TcpConnect);
        assert!(!results[1].success);
        assert!(!results
            .iter()
            .any(|r| r.kind == DiagnosticKind::TlsHandshake));
    }

    #[test]
    fn taban_hedefi_de_coktuyse_sansur_denemez() {
        let targets = vec![Target::baseline("a.test"), Target::probe("b.test")];
        let cokmus = vec![(
            0,
            vec![DiagnosticResult::failed(
                DiagnosticKind::TcpConnect,
                "a.test:443",
                Classification::Timeout,
            )],
        )];
        assert!(!baseline_is_sound(&targets, &cokmus));

        let saglam = vec![(
            0,
            vec![DiagnosticResult::ok(
                DiagnosticKind::TcpConnect,
                "a.test:443",
                Duration::from_millis(20),
            )],
        )];
        assert!(baseline_is_sound(&targets, &saglam));
    }

    #[test]
    fn taban_hedefi_yoksa_sonuc_engellenmiyor() {
        let targets = vec![Target::probe("b.test")];
        assert!(baseline_is_sound(&targets, &[]));
    }
}
