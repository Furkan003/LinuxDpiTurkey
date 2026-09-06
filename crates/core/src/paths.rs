//! Süreçler arası anlaşılan dosya yolları.
//!
//! Motor ve arayüz ayrı programlar; "koruma çalışıyor mu" sorusuna ikisinin
//! de aynı cevabı vermesi gerekiyor. Yolu iki yerde ayrı ayrı yazmak, birinin
//! değişip diğerinin unutulmasıyla sonuçlanır — bu yüzden tek yerde duruyor.
//!
//! Burada yalnızca **sabitler** var; dosyalara dokunan kod platform
//! crate'lerinde.

/// Korumayı yürüten sürecin kimliğinin yazıldığı dosya.
///
/// Yalnızca **koruma kurulduktan sonra** yazılır ve geri alınırken silinir.
/// `trdpi --olc`, `--durdur`, `--geri` gibi geçici çalışmalar buraya
/// dokunmaz: arayüz "çalışıyor" derken korumayı kastetmeli, o an bir komutun
/// açık olmasını değil.
pub const PIDFILE: &str = "/run/trdpi.pid";

/// `/run` yazılamıyorsa kullanılacak yer.
///
/// `/run` her sistemde vardır ama kap (container) ve bazı kurulumlarda salt
/// okunur olabilir. Bu durumda koruma yine çalışmalı.
pub const PIDFILE_FALLBACK: &str = "/var/lib/trdpi/pid";

/// Sürecin `/proc/<pid>/comm` içindeki adı.
///
/// Kimlik dosyası eski kalabilir: süreç `kill -9` ile ölürse dosya durur ve
/// kimlik başka bir programa verilebilir. Bu yüzden kimliği doğrularken
/// sürecin adına da bakılır.
pub const PROCESS_NAME: &str = "trdpi";

/// Koruma **çalıştırmayan** alt komutlar.
///
/// Hepsi `trdpi` adını taşıyor: süreç adına bakan bir kontrol durdurma
/// komutunu, gözcüyü ya da bir ölçümü çalışan koruma sanıyor. Bu, arayüzde
/// "durduruluyor" ekranında takılmaya ve 45 saniye sonra ekranın kendiliğinden
/// "Koruma açık"a dönmesine yol açıyordu.
const KORUMA_DISI: [&str; 11] = [
    "--geri",
    "--durdur",
    "--temizle",
    "--bekci",
    "--dene",
    "--rapor",
    "--olc",
    "--surum",
    "--yardim",
    "--acilista",
    "-h",
];

/// Bu komut satırı koruma çalıştıran bir kopyaya mı ait?
///
/// `cmdline` boşlukla ayrılmış argümanlar. Bilinmeyen bir bayrak koruma
/// sayılıyor: yanlışlıkla "çalışmıyor" demek, kullanıcının korumayı
/// kapattığını sanmasına yol açar — yanlış yönde hata yapmıyoruz.
pub fn is_protection_cmdline(cmdline: &str) -> bool {
    let mut parcalar = cmdline.split_whitespace();
    // Boş komut satırı zombi demektir: ölmüş ama devşirilmemiş bir sürecin
    // `/proc/<pid>/cmdline` dosyası boşalıyor, ama `comm` hâlâ "trdpi"
    // diyor. Bunu koruma sayıyorduk. Gerçekte olan: kullanıcı DURDUR'a
    // basınca durdurma başarıyla bitiyor, ama arkada kalan zombi yüzünden
    // arayüz "hâlâ çalışıyor" görüyor, 45 saniye bekleyip ekranı "Koruma
    // açık"a döndürüyordu. Kullanıcının aylardır "kendiliğinden geri
    // açılıyor" dediği şey buydu; sunucuda ölçüldü.
    if parcalar.next().is_none() {
        return false;
    }
    !parcalar.any(|a| KORUMA_DISI.iter().any(|k| a == *k || a.starts_with("--acilista")))
}

/// Motorun anlık durumunu yazdığı dosya.
///
/// Arayüz motorla doğrudan konuşmuyor; sayaçları ve o an kullanılan tekniği
/// buradan okuyor. Küçük ve satır tabanlı: ayrıştırmak için kütüphane
/// gerekmiyor, yazmak da bir sistem çağrısından ibaret.
pub const STATUS_FILE: &str = "/run/trdpi.durum";

/// Durum dosyasından bir alanı okur.
///
/// Biçim `anahtar=değer`, satır başına bir tane. Bilinmeyen satırlar
/// yoksayılıyor ki ileride alan eklemek eski arayüzü bozmasın.
pub fn status_field<'a>(contents: &'a str, key: &str) -> Option<&'a str> {
    contents
        .lines()
        .filter_map(|l| l.split_once('='))
        // Anahtar da kırpılıyor: yazan taraf yanlışlıkla girinti bırakırsa
        // okuma bundan etkilenmesin.
        .find(|(k, _)| k.trim() == key)
        .map(|(_, v)| v.trim())
}

/// Kimlik dosyasının içeriğinden süreç kimliğini çıkarır.
///
/// Saf fonksiyon: dosya sistemine dokunmaz.
pub fn parse_pid(contents: &str) -> Option<u32> {
    let pid = contents.trim().parse::<u32>().ok()?;
    // 0 ve 1 asla bize ait olamaz; bozuk bir dosya yüzünden init'e sinyal
    // göndermek felaket olurdu.
    (pid > 1).then_some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kimlik_okunuyor() {
        assert_eq!(parse_pid("1234\n"), Some(1234));
        assert_eq!(parse_pid("  42  "), Some(42));
    }

    /// Bozuk dosya yüzünden yanlış sürece sinyal gitmemeli.
    #[test]
    fn bozuk_icerik_reddediliyor() {
        for kotu in [
            "",
            "\n",
            "abc",
            "-1",
            "0",
            "1",
            "12 34",
            "1e3",
            "99999999999999999999",
        ] {
            assert_eq!(parse_pid(kotu), None, "kabul edilmemeliydi: {kotu:?}");
        }
    }
}

#[cfg(test)]
mod durum_testleri {
    use super::*;

    const ORNEK: &str = "baglanti=12
kurulan=11
teknik=yeniden deneme
";

    #[test]
    fn alan_okunuyor() {
        assert_eq!(status_field(ORNEK, "baglanti"), Some("12"));
        assert_eq!(status_field(ORNEK, "teknik"), Some("yeniden deneme"));
    }

    #[test]
    fn olmayan_alan_none() {
        assert_eq!(status_field(ORNEK, "yok"), None);
    }

    #[test]
    fn bozuk_satirlar_yoksayiliyor() {
        // İleride alan eklemek eski arayüzü bozmamalı.
        let s = "cop
baglanti=5
=bos
";
        assert_eq!(status_field(s, "baglanti"), Some("5"));
    }

    #[test]
    fn anahtardaki_girinti_okumayi_bozmuyor() {
        assert_eq!(status_field("   baglanti=7
", "baglanti"), Some("7"));
    }

    #[test]
    fn bos_icerik_panik_yapmiyor() {
        assert_eq!(status_field("", "baglanti"), None);
    }
}

#[cfg(test)]
mod cmdline_testleri {
    use super::*;

    #[test]
    fn parametresiz_calistirma_korumadir() {
        assert!(is_protection_cmdline("/usr/bin/trdpi"));
    }

    #[test]
    fn sure_ile_calistirma_korumadir() {
        assert!(is_protection_cmdline("/usr/bin/trdpi --sure 120"));
        assert!(is_protection_cmdline("/usr/bin/trdpi --quic-gecir"));
    }

    /// Asıl hata buydu: bunların hepsi `trdpi` adını taşıyor.
    #[test]
    fn durdurma_gozcu_ve_olcum_koruma_degil() {
        assert!(!is_protection_cmdline("/usr/bin/trdpi --geri"));
        assert!(!is_protection_cmdline("/usr/bin/trdpi --durdur"));
        assert!(!is_protection_cmdline("/usr/bin/trdpi --temizle"));
        assert!(!is_protection_cmdline("/usr/bin/trdpi --bekci 42 trdpi_redirect_x"));
        assert!(!is_protection_cmdline("/usr/bin/trdpi --dene discord.com"));
        assert!(!is_protection_cmdline("/usr/bin/trdpi --rapor"));
        assert!(!is_protection_cmdline("/usr/bin/trdpi --olc"));
    }

    /// Zombi süreçler koruma sayılmamalı.
    ///
    /// Başlatma çağrısı ölünce arkada zombi kalıyordu; komut satırı boş,
    /// adı hâlâ `trdpi`. Ekran durdurmadan sonra "Koruma açık"a dönüyordu.
    #[test]
    fn bos_komut_satiri_koruma_degil() {
        assert!(!is_protection_cmdline(""));
        assert!(!is_protection_cmdline("   "));
        assert!(!is_protection_cmdline("
"));
    }

    #[test]
    fn acilista_komutlari_koruma_degil() {
        assert!(!is_protection_cmdline("/usr/bin/trdpi --acilista"));
        assert!(!is_protection_cmdline("/usr/bin/trdpi --acilista-ac"));
        assert!(!is_protection_cmdline("/usr/bin/trdpi --acilista-kapat"));
    }

    /// Bilinmeyen bayrakta koruma varsayıyoruz: yanlış "kapalı" demek,
    /// kullanıcının korumayı kapalı sanmasına yol açardı.
    #[test]
    fn bilinmeyen_bayrak_koruma_sayiliyor() {
        assert!(is_protection_cmdline("/usr/bin/trdpi --yeni-bir-sey"));
    }

    /// Boş girdi eskiden koruma sayılıyordu — "bilinmeyen bayrak koruma
    /// sayılır" kuralının yan etkisiydi. Ama boş komut satırı bir bayrak
    /// değil, ölmüş bir süreç: yukarıdaki [`bos_komut_satiri_koruma_degil`]
    /// bunu ölçüyor. Burada kalan tek soru panik yapmaması.
    #[test]
    fn bos_girdi_panik_yapmiyor() {
        let _ = is_protection_cmdline("");
    }
}
