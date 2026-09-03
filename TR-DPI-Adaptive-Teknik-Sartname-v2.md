# TR-DPI Adaptive — Teknik Şartname

## 0. Teknik Karar Özeti

**Önerilen stack**

- Desktop shell: Tauri 2
- Frontend: React + TypeScript + Vite
- Native core: Rust
- Storage: SQLite
- Logging: `tracing`
- Serialization: `serde`
- IPC: Tauri commands + typed DTO
- Windows packet backend: WinDivert adapter
- Linux packet backend: NFQUEUE + nftables
- Linux fallback: local SOCKS5 / transparent proxy
- Packaging: AppImage + deb + rpm + AUR; Windows NSIS installer
- CI: GitHub Actions
- Release signing: mandatory

## 1. Komponentler

```text
desktop-ui
   ↓
tauri-commands
   ↓
orchestrator
 ┌─ diagnostics
 ├─ policy
 ├─ profiles
 ├─ engine
 ├─ storage
 ├─ health
 └─ updater
       ↓
 platform adapter
 ┌───────────────┬─────────────────┐
 Windows         Linux
 WinDivert       NFQUEUE/nftables
               / SOCKS fallback
```

## 2. Klasör yapısı

```text
src-tauri/
├─ src/
│  ├─ main.rs
│  ├─ app.rs
│  ├─ commands/
│  ├─ engine/
│  ├─ diagnostics/
│  ├─ policy/
│  ├─ profiles/
│  ├─ platform/
│  │  ├─ mod.rs
│  │  ├─ windows.rs
│  │  └─ linux.rs
│  ├─ dns/
│  ├─ health/
│  ├─ firewall/
│  ├─ storage/
│  └─ security/
├─ capabilities/
├─ icons/
├─ binaries/
└─ tauri.conf.json

src/
├─ app/
├─ components/
├─ pages/
├─ stores/
├─ services/
├─ types/
└─ styles/
```

## 3. Platform trait

```rust
pub trait NetworkBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> BackendCapabilities;
    fn prepare(&self) -> anyhow::Result<()>;
    fn start(&self, profile: &Profile) -> anyhow::Result<()>;
    fn stop(&self) -> anyhow::Result<()>;
    fn rollback(&self) -> anyhow::Result<()>;
}
```

## 4. Capabilities

```rust
pub struct BackendCapabilities {
    pub packet_interception: bool,
    pub transparent_proxy: bool,
    pub local_proxy: bool,
    pub quic_handling: bool,
    pub dns_control: bool,
    pub requires_admin: bool,
    pub supports_ipv6: bool,
}
```

## 5. Profile schema

```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub protocols: ProtocolPolicy,
    pub strategy: StrategyPolicy,
    pub health: HealthPolicy,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StrategyPolicy {
    pub fragmentation: FragmentationMode,
    pub fake_traffic: FakeTrafficMode,
    pub ttl: TtlMode,
    pub header_strategy: HeaderStrategy,
    pub quic: QuicMode,
}
```

## 6. Diagnostics

Her teşhis testini ortak model ile döndür:

```rust
pub enum DiagnosticKind {
    DnsIntegrity,
    TcpConnect,
    TlsHandshake,
    HttpFetch,
    QuicReachability,
}

pub struct DiagnosticResult {
    pub kind: DiagnosticKind,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub classification: Option<String>,
    pub details: serde_json::Value,
}
```

## 7. Policy engine

Girdi:

```text
NetworkFingerprint
CandidateProfile[]
```

Çıktı:

```text
RankedProfile[]
```

Puanlamada:
- availability
- handshake success
- latency
- reset rate
- packet loss
- DNS integrity
- QUIC health

kullan.

## 8. Rollback tasarımı

Her start öncesi:

```text
snapshot()
transaction()
apply()
verify()
commit()
```

Fail:

```text
rollback()
verify-clean-state()
```

Crash recovery:
- app startup → previous session state oku
- orphan session varsa cleanup helper çağır
- cleanup başarısızsa kullanıcıya “network recovery” ekranı göster

## 9. IPC

Allowlist:

```text
get_capabilities
get_engine_status
run_diagnostics
list_profiles
start_engine
stop_engine
switch_profile
export_debug_report
get_logs
check_update
install_update
```

Renderer'dan arbitrary command kabul etme.

## 10. Privileged helper

### Windows

```text
GUI
 ↓ UAC
helper.exe
 ↓
WinDivert/backend
```

### Linux

```text
GUI
 ↓ polkit
trdpi-helper
 ↓
nft / NFQUEUE
```

Root GUI yasak.

## 11. Linux detection

Sırayla:

```text
os-release
uname
architecture
libc
nft --version
iptables --version
systemctl
pkexec/polkit
nfqueue kernel support
capability check
fuse/dev-fuse
```

Sadece distro adına göre karar verme.

## 12. Linux backend sıralaması

```text
1. NFQUEUE
2. transparent proxy
3. local SOCKS5
4. diagnostic-only
```

## 13. Windows backend

```text
1. packet backend
2. local proxy fallback
3. diagnostic-only
```

## 14. State machine

```text
STOPPED
  ↓
STARTING
  ↓
DIAGNOSING
  ↓
SELECTING
  ↓
APPLYING
  ↓
VERIFYING
  ├── success → RUNNING
  └── fail → ROLLBACK → NEXT_PROFILE
```

## 15. Logs

JSON Lines:

```json
{
  "ts":"2026-09-03T20:00:00Z",
  "level":"INFO",
  "module":"policy",
  "event":"profile_selected",
  "profile":"tr-balanced"
}
```

Trafik içeriği loglama.

## 16. SQLite

Tablolar:

```text
profiles
sessions
diagnostics
settings
snapshots
updates
```

## 17. Update güvenliği

Update manifest:

```json
{
  "version":"1.2.0",
  "platform":"windows-x64",
  "artifact":"...",
  "sha256":"...",
  "signature":"..."
}
```

İmzalanmamış artifact kurulmasın.

## 18. UI

### Ana sayfa
- status
- start/stop
- active profile
- health score
- network label
- last diagnostic

### Diagnostics
- DNS
- TCP
- TLS
- QUIC
- classification

### Settings
- start on boot
- default profile
- language
- privacy
- advanced

## 19. Accessibility

- keyboard navigation
- screen reader labels
- focus states
- no color-only status
- Turkish + English

## 20. Testing matrix

### Windows
- 10 x64
- 11 x64
- clean machine
- existing VPN
- existing firewall
- restart during active session

### Linux
- Ubuntu 22.04
- Ubuntu 24.04
- Debian 12
- Debian 13
- Arch rolling
- Fedora
- Linux Mint
- Manjaro
- CachyOS

### Failure tests
- FUSE missing
- nft missing
- NFQUEUE unavailable
- helper denied
- stale firewall rules
- DNS broken
- IPv6 only
- dual-stack
- suspended/resumed laptop

## 21. Acceptance criteria

```text
PASS if:
- installation completes
- helper starts
- profile applies
- health check passes
- stop restores previous state
- crash recovery clears orphan state
```

## 22. Vibe-coding constraint

AI tarafından üretilen her backend change için:

```text
1. explain capability impact
2. add unit test
3. add rollback path
4. add log event
5. add error handling
6. don't silently alter firewall
```

## 23. Build commands (conceptual)

```bash
pnpm install
pnpm tauri dev
pnpm tauri build
```

Windows:
```text
bundle -> NSIS setup.exe
```

Linux:
```text
bundle -> AppImage
```

Tauri docs:
- https://v2.tauri.app/distribute/
- https://v2.tauri.app/distribute/appimage/
- https://tauri.app/distribute/windows-installer/


# 24. ÜRÜN HEDEFİ — ZERO-TERMINAL LINUX

Linux kullanıcı deneyimi için ürün requirement'ı:

> Kullanıcı terminal açmadan, nftables/iptables/nfqueue/systemd/proxy/DNS ayarı yazmadan sistemi hazırlayabilmeli.

Bu bir UX requirement'ıdır.

## 24.1 Kabul edilemez akış

```text
AppImage indir
↓
terminal aç
↓
sudo ...
↓
nft ...
↓
systemctl ...
↓
DNS değiştir
↓
uygulamayı çalıştır
```

## 24.2 Kabul edilen akış

```text
AppImage indir
↓
uygulamayı aç
↓
[Kur ve Başlat]
↓
grafiksel yetki penceresi
↓
otomatik capability detection
↓
otomatik backend
↓
otomatik profile
↓
AKTİF
```

# 25. Privilege Broker

GUI:
- root/admin değil

Broker:
- imzalı/yerel
- minimum command surface
- sadece gerekli network işlemleri

Örneğin RPC:

```text
prepare_backend
apply_network_state
verify_network_state
rollback_network_state
install_autostart
remove_autostart
```

Broker arbitary shell komutu kabul etmemeli.

# 26. Linux Capability Engine

```rust
struct LinuxCapabilities {
    nftables: bool,
    nfqueue: bool,
    transparent_proxy: bool,
    local_proxy: bool,
    polkit: bool,
    systemd: bool,
    openrc: bool,
    fuse: bool,
    ipv6: bool,
}
```

Distro name yalnızca UI bilgi alanı olsun.

Backend kararını capability engine versin.

# 27. Resource Ownership

Uygulamanın yarattığı her sistem objesi ownership tag taşımalı:

```text
owner=trdpi
session=<uuid>
```

Stop ve uninstall yalnızca `owner=trdpi` objelerini geri almalı.

# 28. Network State Snapshot

Snapshot sınırlı ve güvenli olmalı.

Örnek:

```json
{
  "sessionId": "uuid",
  "interfaces": [],
  "ownedFirewallObjects": [],
  "ownedRoutes": [],
  "ownedListeners": [],
  "ownedServices": []
}
```

Başka uygulamaların kurallarını yedekle/sil mantığı geliştirme.

# 29. Backend Registry

```text
BackendRegistry
├── zapret2
├── goodbyedpi [windows]
├── byedpi
├── proxy
└── dns
```

Her backend:

```text
probe
prepare
apply
verify
stop
rollback
```

metotlarını uygular.

# 30. Adaptive Selection

Pseudocode:

```text
capabilities = detect()
baseline = diagnostics()

candidates = registry
  .filter(supported(capabilities))
  .filter(reasonable_for(baseline))

for candidate in rank(candidates):
    snapshot = candidate.prepare()
    candidate.apply(profile)
    health = candidate.verify()

    if health.score >= threshold:
        commit(snapshot)
        return RUNNING

    candidate.rollback(snapshot)

return FALLBACK_PROXY
```

# 31. UI-State Contract

Backend'in ne yaptığı yerine sonuç göster:

```text
Starting...
Diagnosing...
Applying best method...
Checking connection...
Protected
```

Teknik ekran:

```text
Backend
Engine
Profile
Health
Diagnostics
```

# 32. Linux First-Run Error UX

Örnek:

```text
Bazı sistem yetkileri gerekli.

TR-DPI Adaptive yalnızca ağ bağlantısı için gereken
işlemlere erişim isteyecek.

[ Devam ]
```

Ardından polkit ekranı.

Yetki reddedilirse:

```text
Yönetici yetkisi verilmedi.
Sistem geneli mod yerine yerel proxy modu
kullanılabilir.

[ Yerel Modu Kullan ]
```

# 33. Uninstall

Kaldırma akışı:

```text
disable engine
↓
rollback owned firewall/routing
↓
stop helper/service
↓
remove autostart
↓
remove app data (optional)
↓
uninstall
```

Kullanıcı terminal komutu görmez.

# 34. Crash Recovery

Helper yaşamaya devam ederse:
- watchdog
- session lease
- startup orphan cleanup

kullan.

Her aktif session için:

```text
heartbeat
expiry
cleanup token
```

tutulabilir.

# 35. Third-Party Engine Packaging

Bir upstream engine gömülecekse:
- lisans doğrula
- sürüm pinle
- checksum doğrula
- kendi CI'ın içinde artifact üret
- release ile engine sürümünü ilişkilendir

Kullanıcıya “şunu ayrıca indir” denmemeli.

# 36. Vibe Coding için kesin kural

AI agent hiçbir zaman:

```text
“terminalde şu komutu çalıştır”
```

diye kullanıcıya çözüm bırakamaz.

Bunun yerine:
- native helper
- IPC
- capability detection
- error state
- rollback

implement etmelidir.

