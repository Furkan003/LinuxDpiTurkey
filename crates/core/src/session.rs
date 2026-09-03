//! Oturum kimliği ve sistem objesi sahipliği.
//!
//! Uygulamanın yarattığı her sistem objesi (nftables table/chain, proxy listener,
//! route) bir oturuma ait olarak etiketlenir. `stop` ve `uninstall` yalnızca bu
//! etiketi taşıyan objeleri geri alır — başka uygulamaların kuralları asla
//! yedeklenmez veya silinmez.
//!
//! ## Neden UUID değil
//!
//! Denetim C1: UUID tire içerir, nftables identifier'larında tire tırnaksız
//! kullanılamaz. Bu yüzden oturum kimlikleri tiresiz onaltılık üretilir ve
//! ürettiğimiz her isim `[A-Za-z][A-Za-z0-9_]*` biçimini korur.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Uygulamanın oluşturduğu sistem objelerinin isim öneki.
pub const OWNER_PREFIX: &str = "trdpi";

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Bir motor oturumunun kimliği. 16 haneli onaltılık, tire içermez.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    /// Yeni bir oturum kimliği üretir.
    ///
    /// Tek makinede çalışan tek uygulama için zaman + sayaç yeterli benzersizliği
    /// verir; kriptografik rastgelelik amaçlanmamıştır.
    pub fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        SessionId(format!(
            "{:012x}{:04x}",
            nanos & 0xffff_ffff_ffff,
            seq & 0xffff
        ))
    }

    /// Var olan bir kimliği doğrulayarak sarmalar (state dosyasından okurken).
    ///
    /// Yalnızca onaltılık haneler kabul edilir; başka her şey reddedilir ki
    /// disk üzerindeki bozuk bir state dosyası sistem objesi ismine sızamasın.
    pub fn parse(raw: &str) -> Result<Self, InvalidSessionId> {
        if raw.is_empty() || raw.len() > 32 {
            return Err(InvalidSessionId);
        }
        if !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(InvalidSessionId);
        }
        Ok(SessionId(raw.to_ascii_lowercase()))
    }

    /// Ham kimlik dizesi.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Bu oturuma ait bir sistem objesi ismi üretir.
    ///
    /// Örnek: `nft_table` → `trdpi_nft_table_a1b2c3d4e5f60000`
    ///
    /// Sonuç daima `[A-Za-z][A-Za-z0-9_]*` biçimindedir, yani nftables
    /// identifier'ı olarak tırnaksız kullanılabilir.
    pub fn object_name(&self, role: &str) -> String {
        debug_assert!(
            role.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "obje rolü yalnızca alfanumerik ve alt çizgi içerebilir: {role}"
        );
        format!("{OWNER_PREFIX}_{role}_{}", self.0)
    }

    /// Verilen ismin bu oturuma ait olup olmadığını söyler.
    ///
    /// Temizlik yalnızca `true` dönen objelere dokunur.
    pub fn owns(&self, object_name: &str) -> bool {
        object_name.starts_with(OWNER_PREFIX) && object_name.ends_with(&self.0)
    }

    /// İsmin, hangi oturuma ait olursa olsun, bu uygulama tarafından
    /// oluşturulmuş olup olmadığını söyler. Yetim (orphan) temizliği bunu kullanır.
    pub fn is_owned_by_app(object_name: &str) -> bool {
        object_name
            .strip_prefix(OWNER_PREFIX)
            .is_some_and(|rest| rest.starts_with('_'))
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// [`SessionId::parse`] geçersiz girdi aldığında döner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("geçersiz oturum kimliği: yalnızca onaltılık haneler, 1-32 karakter")]
pub struct InvalidSessionId;

#[cfg(test)]
mod tests {
    use super::*;

    /// Denetim C1'in gerileme testi.
    #[test]
    fn kimlik_nftables_icin_gecerli() {
        for _ in 0..64 {
            let id = SessionId::new();
            let name = id.object_name("nft_table");

            assert!(
                !name.contains('-'),
                "nft identifier'ı tire içeremez: {name}"
            );

            let mut bytes = name.bytes();
            assert!(bytes.next().is_some_and(|b| b.is_ascii_alphabetic()));
            assert!(bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        }
    }

    #[test]
    fn kimlikler_benzersiz() {
        let ids: std::collections::HashSet<_> = (0..1000).map(|_| SessionId::new()).collect();
        assert_eq!(ids.len(), 1000);
    }

    #[test]
    fn sahiplik_kendi_objesini_taniyor() {
        let mine = SessionId::new();
        let other = SessionId::new();

        let name = mine.object_name("proxy");
        assert!(mine.owns(&name));
        assert!(!other.owns(&name));
        assert!(SessionId::is_owned_by_app(&name));
    }

    #[test]
    fn baskasinin_objesine_dokunmuyoruz() {
        for foreign in ["docker0", "ufw-before-input", "ts-input", "KUBE-SERVICES"] {
            assert!(!SessionId::is_owned_by_app(foreign), "{foreign}");
            assert!(!SessionId::new().owns(foreign), "{foreign}");
        }
    }

    #[test]
    fn parse_bozuk_girdiyi_reddediyor() {
        assert!(SessionId::parse("a1b2c3d4").is_ok());
        assert!(SessionId::parse("").is_err());
        assert!(
            SessionId::parse("550e8400-e29b-41d4").is_err(),
            "tireli UUID"
        );
        assert!(SessionId::parse("../../etc/passwd").is_err());
        assert!(SessionId::parse("nft flush ruleset").is_err());
    }
}
