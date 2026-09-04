//! # trdpi-dns
//!
//! Çalışan bir adres çözümleyici bulur ve sistemi ona yönlendirir.
//!
//! ## Neden kendi DNS sunucumuzu yazmıyoruz
//!
//! Sistemin çözümleyicisi zaten standart dışı bir kapıya yönlendirilebiliyor.
//! Araya bir sunucu daha koymak, çözmediği bir sorun için yeni bir arıza
//! kaynağı eklemek olurdu. Bize gereken tek şey **çalışan üst kaynağı bulmak**
//! ve yönlendirmeyi geri alınabilir biçimde yapmak.
//!
//! ## Ölçülen gerçek
//!
//! Test ettiğimiz hatta 53. porttaki dış çözümleyicilerin tamamı kapalı, ve
//! sistemin çözümleyicisi engellenen alan adları için bilinen sansür adresini
//! döndürüyor. Bu yüzden aday listesi denenerek seçilir, sabit değildir.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod resolver;
pub mod upstream;
pub mod wire;

pub use resolver::{ResolverConfig, ResolverError, ResolverManager};
pub use upstream::{ProbeOutcome, Upstream};
pub use wire::{answers_disagree, is_censorship_response, query, DnsAnswer, DnsError};

/// Üst kaynak ararken kullanılan, engellenmesi beklenen alan adı.
///
/// Engellenmemiş bir adla test etmek yanıltıcı olur: ele geçirilmiş bir
/// çözümleyici de o ad için doğru cevap verir.
pub const DEFAULT_CANARY: &str = "discord.com";
