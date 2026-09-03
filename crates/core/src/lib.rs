//! # trdpi-core
//!
//! TR-DPI Adaptive'in **tek normatif sözleşme kaynağı**.
//!
//! `TR-DPI-Adaptive-*.md` dosyaları gerekçe ve arka plan belgeleridir; tip tanımı
//! için normatif değildir. Aynı yapının o dosyalarda birden fazla, birbiriyle
//! çelişen tanımı bulunduğu için (bkz. `TR-DPI-Adaptive-Dokuman-Denetimi-v1.md`)
//! kanonik tanım buraya taşınmıştır. Derleyici burada tek tanım olmasını zorlar.
//!
//! ## Bu crate'in sınırları
//!
//! - I/O yok, ağ erişimi yok, platform kodu yok, `unsafe` yok.
//! - Her şey gerçek bir ağ backend'i olmadan unit-test edilebilir olmalıdır.
//! - Ayrıcalık gerektiren hiçbir şey burada durmaz.
//!
//! ## Denetim bulgularının karşılıkları
//!
//! | Bulgu | Karşılık |
//! |---|---|
//! | A1 — dört farklı `Profile` | [`profile::Profile`] tek tanım |
//! | A2 — snapshot'sız `rollback` | [`backend::Backend::rollback`] `Snapshot` alır |
//! | A3 — eksik ara durumlar | [`state::EngineState`] on bir durum + [`state::EngineState::user_message`] |
//! | B1 — "backend" iki anlamda | [`capability::Mechanism`] ve [`backend::EngineId`] ayrıldı |
//! | B2 — iki skorlama modeli | [`score`] tek fonksiyon |
//! | B3 — üç farklı sınıflandırma | [`classify::Classification`] tek enum |
//! | C1 — nft'de geçersiz UUID | [`session::SessionId`] tiresiz hex |
//! | C5 — üç farklı capability | [`capability::Capabilities`] tek struct |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
pub mod capability;
pub mod classify;
pub mod diagnostics;
pub mod profile;
pub mod score;
pub mod session;
pub mod state;

pub use backend::{Backend, BackendError, EngineId, ProbeContext, ProbeResult, Snapshot};
pub use capability::{Capabilities, Mechanism};
pub use classify::Classification;
pub use diagnostics::{DiagnosticKind, DiagnosticResult, NetworkFingerprint};
pub use profile::{Profile, ProfileId, RiskLevel};
pub use score::{HealthReport, HealthScore, ScoreWeights};
pub use session::SessionId;
pub use state::EngineState;
