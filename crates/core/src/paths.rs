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
