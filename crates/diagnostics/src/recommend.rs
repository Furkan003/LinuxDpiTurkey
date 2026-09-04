//! Ölçümden eyleme geçiş.
//!
//! Kullanıcı DPI tekniklerini bilmek zorunda değil. `Sınıf: timeout` gibi bir
//! çıktı ona hiçbir şey söylemez; ne yapması gerektiğini söylemek bu modülün
//! işi.
//!
//! Sıra önemlidir: DNS sorunu varsa önce o çözülmelidir, çünkü yanlış adrese
//! bağlanılırken paket tekniklerinin hiçbiri işe yaramaz.

use trdpi_core::{Classification, DiagnosticResult, NetworkFingerprint};

/// Ölçüm sonucundan çıkan öneri.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recommendation {
    /// Tek cümlelik teşhis.
    pub summary: String,
    /// Bu sonuca neden varıldığı.
    pub reason: String,
    /// Sırayla yapılacaklar. Boşsa yapılacak bir şey yok.
    pub steps: Vec<String>,
}

impl Recommendation {
    fn new(summary: &str, reason: &str, steps: &[&str]) -> Self {
        Self {
            summary: summary.to_owned(),
            reason: reason.to_owned(),
            steps: steps.iter().map(|s| (*s).to_owned()).collect(),
        }
    }
}

/// Sonuçlarda belirli bir ayrıntının geçip geçmediği.
fn detayda(results: &[DiagnosticResult], parca: &str) -> bool {
    results
        .iter()
        .any(|r| r.detail.as_deref().is_some_and(|d| d.contains(parca)))
}

/// Ölçüm sonuçlarından öneri üretir.
pub fn recommend(results: &[DiagnosticResult]) -> Recommendation {
    let fp = NetworkFingerprint::from_results(results);
    let overall = NetworkFingerprint::overall(results);

    // 1. DNS her şeyden önce gelir.
    if fp.dns_tampering {
        return Recommendation::new(
            "Sana yanlış adresler veriliyor.",
            "Adres çözümlemesi, bağımsız kaynakların verdiğinden farklı ve çalışmayan \
             adresler döndürüyor.",
            &[
                "Bilgisayarının adres çözümleme ayarını değiştir (1.1.1.1 veya 8.8.8.8).",
                "Değiştirdikten sonra bu ölçümü tekrar çalıştır.",
                "Sorun sürerse engel başka yerde demektir; sonucu bildir.",
            ],
        );
    }

    // 2. Bağlantı kurulup da güvenli aşamada kesiliyorsa sahte paket yöntemi
    //    tam bu duruma karşı çalışır.
    if fp.tls_reset {
        return Recommendation::new(
            "Güvenli bağlantı kurulurken araya giriliyor.",
            "Bağlantı kuruluyor ama site adı gönderildikten hemen sonra kesiliyor. \
             Sahte paket yöntemi tam bu duruma karşı tasarlandı.",
            &[
                "sudo ./trdpi --ttl 5",
                "Açılmazsa --ttl 3 ve --ttl 7 dene.",
                "Hangisinde açıldığını not et.",
            ],
        );
    }

    // 3. Bağlantı hiç kurulamıyor. Adresin ayakta olup olmaması farklı
    //    çözümler gerektirir.
    if overall == Classification::Timeout || fp.tcp_reset {
        if detayda(results, "adres ayakta") {
            return Recommendation::new(
                "Sunucuya ulaşılıyor ama bağlantı kapısı kapatılmış.",
                "Adres başka bir kapıdan yanıt veriyor, yalnızca kullandığımız kapı \
                 engelleniyor. Bu, bağlantı kurulmadan önce uygulanan bir engel.",
                &[
                    "Sahte paket yöntemi burada işe yaramaz — devreye gireceği an hiç gelmiyor.",
                    "Bu sonucu bildir; bağlantı kurulma aşamasına yönelik bir yöntem gerekiyor.",
                ],
            );
        }
        if detayda(results, "hiçbir kapıdan ulaşılamıyor") {
            return Recommendation::new(
                "Verilen adrese hiçbir şekilde ulaşılamıyor.",
                "Adres hiçbir kapıdan yanıt vermiyor. Ya adres yanlış, ya da tamamen \
                 engellenmiş.",
                &[
                    "Adres çözümleme ayarını değiştirip tekrar ölç — farklı adres gelebilir.",
                    "Sonuç değişmezse bildir.",
                ],
            );
        }
        return Recommendation::new(
            "Bağlantı kurulamıyor ama sebebi netleşmedi.",
            "Ölçüm, bağlantının neden kurulamadığını ayırt edemedi.",
            &["Ölçümü birkaç kez tekrarla; sonuç değişiyorsa bildir."],
        );
    }

    if overall == Classification::Unknown {
        return Recommendation::new(
            "Yeterli ölçüm yapılamadı.",
            "Bağlantı yeterince ölçülemedi. Bu, sorun olmadığı anlamına gelmez.",
            &["İnternet bağlantını kontrol edip tekrar dene."],
        );
    }

    if fp.throttling {
        return Recommendation::new(
            "Bağlantın kasıtlı olarak yavaşlatılıyor olabilir.",
            "Bağlantı kuruluyor ama olağandışı yavaş.",
            &["Ölçümü farklı saatlerde tekrarla; süreler değişiyorsa bildir."],
        );
    }

    Recommendation::new(
        "Ölçülen hedeflerde engelleme belirtisi yok.",
        "Adres çözümlemesi, bağlantı ve güvenli el sıkışma sorunsuz.",
        &[],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use trdpi_core::DiagnosticKind;

    fn hata(kind: DiagnosticKind, c: Classification, detay: Option<&str>) -> DiagnosticResult {
        let r = DiagnosticResult::failed(kind, "ornek.test", c);
        match detay {
            Some(d) => r.with_detail(d),
            None => r,
        }
    }

    /// Hem DNS hem TLS sorunu varsa önce DNS çözülmeli; yanlış adrese
    /// bağlanırken paket teknikleri anlamsız.
    #[test]
    fn dns_sorunu_her_seyden_once_gelir() {
        let r = recommend(&[
            hata(
                DiagnosticKind::DnsIntegrity,
                Classification::DnsTampered,
                None,
            ),
            hata(
                DiagnosticKind::TlsHandshake,
                Classification::TlsInterference,
                None,
            ),
        ]);
        assert!(r.summary.contains("yanlış adres"), "{}", r.summary);
        assert!(!r.steps.iter().any(|s| s.contains("--ttl")));
    }

    #[test]
    fn tls_mudahalesinde_sahte_paket_onerilir() {
        let r = recommend(&[hata(
            DiagnosticKind::TlsHandshake,
            Classification::TlsInterference,
            None,
        )]);
        assert!(r.steps.iter().any(|s| s.contains("trdpi --ttl")));
    }

    /// Bağlantı hiç kurulmuyorsa sahte paket motorunu önermek yanlış olur:
    /// motorun devreye gireceği an hiç gelmiyor.
    #[test]
    fn baglanti_kurulamadiginda_sahte_paket_onerilmez() {
        let r = recommend(&[hata(
            DiagnosticKind::TcpConnect,
            Classification::Timeout,
            Some("TimedOut — adres ayakta (80 kapısı açılıyor), engel bu kapıya özel"),
        )]);
        assert!(!r.steps.iter().any(|s| s.contains("--ttl")));
        assert!(r.summary.contains("kapı"), "{}", r.summary);
    }

    #[test]
    fn olu_adres_ayirt_ediliyor() {
        let r = recommend(&[hata(
            DiagnosticKind::TcpConnect,
            Classification::Timeout,
            Some("TimedOut — adrese hiçbir kapıdan ulaşılamıyor"),
        )]);
        assert!(r.summary.contains("ulaşılamıyor"));
        assert!(!r.steps.is_empty());
    }

    #[test]
    fn temiz_agda_yapilacak_bir_sey_yok() {
        let r = recommend(&[DiagnosticResult::ok(
            DiagnosticKind::TlsHandshake,
            "ornek.test",
            Duration::from_millis(20),
        )]);
        assert!(r.steps.is_empty());
    }

    /// Ölçüm yokluğu "sorun yok" sayılmamalı.
    #[test]
    fn olcum_yoksa_temiz_denmiyor() {
        let r = recommend(&[]);
        assert!(!r.steps.is_empty());
        assert!(r.summary.contains("Yeterli ölçüm"));
    }

    /// Öneriler kullanıcının anlayacağı dilde olmalı.
    #[test]
    fn onerilerde_teknik_jargon_yok() {
        let ornekler = [
            vec![hata(
                DiagnosticKind::DnsIntegrity,
                Classification::DnsTampered,
                None,
            )],
            vec![hata(
                DiagnosticKind::TlsHandshake,
                Classification::TlsInterference,
                None,
            )],
            vec![hata(
                DiagnosticKind::TcpConnect,
                Classification::Timeout,
                None,
            )],
            vec![hata(
                DiagnosticKind::QuicReachability,
                Classification::QuicBlocked,
                None,
            )],
        ];
        for ornek in ornekler {
            let r = recommend(&ornek);
            let metin = format!("{} {}", r.summary, r.reason).to_lowercase();
            for jargon in [
                "nfqueue",
                "nftables",
                "sni",
                "desync",
                "clienthello",
                "tcp",
                "dns",
            ] {
                assert!(!metin.contains(jargon), "'{jargon}' geçiyor: {metin}");
            }
        }
    }

    /// Her öneri ya bir adım vermeli ya da "sorun yok" demeli; arada kalan
    /// bir durum kullanıcıyı boşlukta bırakır.
    #[test]
    fn her_oneri_ya_adim_verir_ya_temiz_der() {
        let durumlar = [
            Classification::Healthy,
            Classification::Degraded,
            Classification::Throttled,
            Classification::QuicBlocked,
            Classification::DnsTampered,
            Classification::TcpReset,
            Classification::TlsInterference,
            Classification::Timeout,
            Classification::Unknown,
        ];
        for c in durumlar {
            let r = recommend(&[hata(DiagnosticKind::HttpFetch, c, None)]);
            assert!(!r.summary.is_empty(), "{c}");
            assert!(!r.reason.is_empty(), "{c}");
            if r.steps.is_empty() {
                assert!(
                    r.summary.contains("belirtisi yok"),
                    "{c}: adım da yok, temiz de demiyor — kullanıcı ne yapacak?"
                );
            }
        }
    }
}
