# TR-DPI Adaptive — Vibe Coding Master Plan

Bu dosya doğrudan Claude Code / Cursor / Codex benzeri ajanlara verilebilecek proje geliştirme planıdır.

## 1. Product Brief

Build a modern cross-platform desktop application for diagnosing and mitigating user-facing DPI/network censorship conditions on Windows and Linux, with a Turkey-first adaptive profile system.

The application must feel like a normal consumer desktop product, not a CLI wrapper.

Primary actions:
- Start
- Stop
- Auto Diagnose
- Select Profile
- View Health

Platforms:
- Windows 10/11 x64
- Linux x86_64 via AppImage
- Linux compatibility layer for Ubuntu/Debian/Arch/Fedora-family systems

## 2. Non-negotiable architecture

```text
Tauri UI
  ↓
Rust Orchestrator
  ↓
Platform Adapter
  ├─ Windows packet backend
  ├─ Linux NFQUEUE backend
  └─ local proxy fallback
```

Never put packet logic inside the React renderer.

## 3. Phase 1 — Shell

Build:
- Tauri app
- React UI
- dark theme
- Turkish/English
- pages
- typed frontend state

Pages:
```text
Home
Diagnostics
Profiles
Logs
Settings
About
```

Deliverable:
- UI works without backend
- fake engine state

## 4. Phase 2 — Rust domain model

Create:
- EngineState
- Profile
- DiagnosticResult
- NetworkFingerprint
- BackendCapabilities
- Session
- Snapshot

Add serde tests.

## 5. Phase 3 — IPC

Implement:
```text
get_engine_status()
get_capabilities()
run_diagnostics()
list_profiles()
start_engine()
stop_engine()
switch_profile()
```

Reject unknown/invalid requests.

## 6. Phase 4 — Diagnostics

Implement baseline tests:
- DNS
- TCP connect
- TLS handshake
- HTTPS fetch
- QUIC reachability

Return:
```text
healthy
degraded
dns_tampered
tcp_reset
tls_interference
throttled
quic_blocked
unknown
```

## 7. Phase 5 — Policy engine

Implement deterministic rules first.

Example:

```text
DNS bad → prioritize DNS strategy
TLS reset → prioritize TLS strategies
QUIC only bad → prioritize QUIC handling
latency spike → test throttling classification
all fail → proxy fallback
```

Don't use ML in MVP.

## 8. Phase 6 — Profile system

Create:
```text
automatic
conservative
balanced
aggressive
manual
```

Each profile must have:
- id
- name
- description
- risk
- supported backends
- protocol policy
- health threshold

## 9. Phase 7 — Linux backend

Implement abstraction first.

Capabilities:
```text
supports_nfqueue
supports_nftables
supports_transparent_proxy
supports_local_proxy
supports_ipv6
```

Startup:
```text
detect
→ choose backend
→ create snapshot
→ apply
→ verify
```

Shutdown:
```text
stop
→ rollback
→ verify clean
```

Never assume systemd.

## 10. Phase 8 — Windows backend

Implement:
- privileged helper
- packet backend abstraction
- lifecycle
- rollback
- logging

Do not let renderer call low-level APIs.

## 11. Phase 9 — Adaptive monitor

Every N seconds:
```text
health probes
↓
score
↓
if degraded:
    try recovery
```

Add:
- profile cooldown
- hysteresis
- maximum strategy switches
- circuit breaker

Do not create infinite profile oscillation.

## 12. Phase 10 — UI polish

Home:
```text
ACTIVE
Healthy
Profile
Network
Latency
[Stop]
```

Diagnostics:
```text
DNS       PASS
TCP       PASS
TLS       DEGRADED
QUIC      BLOCKED
```

Use a non-technical explanation:
> “Bağlantınızda TLS seviyesinde müdahale belirtisi görüldü.”

## 13. Phase 11 — Packaging

Windows:
```text
TR-DPI-Setup-x64.exe
```

Linux:
```text
TR-DPI-x86_64.AppImage
```

Also produce:
```text
.deb
.rpm
AUR metadata
```

## 14. Phase 12 — Signing

Build pipeline:
```text
build
→ test
→ package
→ hash
→ sign
→ release
```

Do not publish unsigned production artifacts.

## 15. Phase 13 — Recovery

Test:
- app kill
- PC reboot
- helper crash
- power loss
- engine startup failure
- firewall apply failure

After every failure, system networking must be restored.

## 16. Phase 14 — Diagnostics export

Create ZIP:
```text
app-version.txt
platform.txt
engine.txt
capabilities.json
diagnostics.json
recent-logs.jsonl
profile.json
```

Do not include:
- full browsing history
- payload
- credentials
- cookies
- arbitrary packet captures

unless the user explicitly enables a separate debug feature.

## 17. Phase 15 — Performance

Benchmarks:
- startup
- memory
- CPU
- diagnostic duration
- profile switch duration
- rollback duration

Target:
```text
GUI cold start < 1.5s
diagnostic < 8s
rollback < 2s
```

## 18. Phase 16 — Security review

Checklist:
```text
[ ] no shell from renderer
[ ] no root GUI
[ ] signed updates
[ ] schema validation
[ ] no arbitrary remote binary execution
[ ] secure temp files
[ ] permissions minimized
[ ] logs sanitized
[ ] IPC allowlist
```

## 19. Prompt for each coding agent

Use this exact style:

> You are working on TR-DPI Adaptive, a cross-platform Tauri 2 + Rust + React application.
>
> Before editing code:
> 1. inspect the repository
> 2. identify the architecture boundary involved
> 3. preserve platform abstraction
> 4. do not move privileged logic into the renderer
>
> For every implementation:
> - add types
> - add error handling
> - add structured logs
> - add tests
> - keep rollback path
> - preserve Linux portability
> - preserve Windows portability
>
> Never silently change firewall state.
> Never run the GUI as root/admin.
> Never add remote telemetry by default.
> Never hardcode one ISP as the only supported network.
> Prefer capability detection over distro-name detection.
> Prefer behavior fingerprints over ISP-name-only presets.

## 20. Prompt for UI agent

> Create a premium dark desktop networking utility UI.
>
> Visual style:
> - minimal
> - modern
> - technical but approachable
> - no “hacker” cliché
> - strong typography
> - subtle status indicators
> - clear primary action
>
> The main screen should make a non-technical user understand:
> - whether the app is running
> - whether the connection is healthy
> - which profile is active
> - whether an intervention was detected
>
> Hide complexity behind Advanced settings.

## 21. Prompt for backend agent

> Implement the Rust orchestration layer only.
>
> Do not implement platform packet interception directly in the orchestrator.
> Define traits and adapters.
> Add:
> - state machine
> - profile loader
> - policy engine
> - diagnostics interface
> - rollback transaction
> - structured events
>
> Everything must be unit-testable without requiring a real network backend.

## 22. Prompt for Linux agent

> Implement Linux capability detection and backend abstraction.
>
> Support:
> - nftables detection
> - NFQUEUE availability detection
> - systemd optional
> - polkit/pkexec detection
> - FUSE detection
> - local SOCKS fallback
>
> Never assume Ubuntu-specific commands are available.
> Never assume systemd exists.

## 23. Prompt for Windows agent

> Implement Windows privileged helper lifecycle and backend abstraction.
>
> Requirements:
> - UAC
> - service lifecycle
> - rollback
> - clean stop
> - crash cleanup
> - structured logs
>
> Do not expose privileged commands to the UI renderer.

## 24. Definition of success

The product is ready for public alpha when:

```text
Windows install works
Linux AppImage works
Ubuntu works
Debian works
Arch works
GUI never needs root/admin
Auto diagnostics works
At least 3 profiles work
Rollback works
Crash recovery works
Logs work
Signed release works
```

## 25. Product principle

The app should not compete by having the largest number of flags.

It should compete by having the best:

```text
diagnosis
+
automatic strategy selection
+
reliability
+
rollback
+
user experience
```


# 26. PRIMARY PRODUCT REQUIREMENT — ZERO TERMINAL

The product is specifically designed so Linux users do NOT need to:
- open Terminal
- run sudo
- edit nftables
- edit iptables
- edit systemd units
- change DNS manually
- configure a system proxy manually
- install Zapret/ByeDPI separately

The application performs the required setup internally through a small privileged helper.

## 26.1 UX contract

Desired:

```text
Download AppImage
      ↓
Open app
      ↓
Automatic check
      ↓
[ Allow required access ]
      ↓
Automatic setup
      ↓
Automatic diagnosis
      ↓
Automatic profile
      ↓
Running
```

## 26.2 NEVER DO THIS

Do not make README instructions like:

```bash
sudo nft ...
sudo systemctl ...
sudo ...
```

for normal end users.

Developer documentation can contain internal commands, but consumer UX cannot depend on them.

# 27. Linux Privilege Architecture

```text
React/Tauri GUI
       |
       v
Rust Orchestrator
       |
       v
Privilege Broker
       |
       +--> polkit
       |
       v
trdpi-helper
       |
       +--> nftables
       +--> NFQUEUE
       +--> proxy listener
       +--> routing
       +--> cleanup
```

GUI must remain non-root.

# 28. Adapter-First Design

Do NOT couple orchestrator to Zapret2/GoodbyeDPI directly.

Create:

```text
BackendRegistry
  ├── Zapret2Adapter
  ├── GoodbyeDPIAdapter
  ├── ByeDPIAdapter
  └── ProxyAdapter
```

The registry chooses based on capabilities + diagnosis.

# 29. Use the Existing Ecosystem as Engines, Not as User Workflows

Reference implementations:
- GoodbyeDPI-Turkey → Turkey-specific operational lessons
- SplitWire-Turkey → multi-method GUI/orchestration lessons
- Zapret2 → cross-platform packet-engine capabilities and blockcheck concept
- GoodbyeDPI → Windows packet backend and simple fragmentation strategies
- ByeDPI/SpoofDPI → proxy-style fallback model

The product layer must hide this complexity.

# 30. Automatic Diagnosis

Implement:

```text
detectEnvironment()
runBaseline()
classifyFailure()
rankBackends()
rankProfiles()
apply()
verify()
recover()
```

No ML in MVP.

# 31. Linux Capability Probe

Implement checks for:

```text
kernel
architecture
libc
nftables
NFQUEUE
polkit
systemd
OpenRC
FUSE
IPv6
network interfaces
existing VPN/proxy conflicts
```

Do not hardcode Ubuntu commands.

# 32. Existing Network Stack Detection

Detect:
- NetworkManager
- systemd-resolved
- resolvconf
- connman
- NetworkManager VPN profiles
- WireGuard
- Tailscale
- Docker
- existing local proxy ports

Do not destroy or overwrite unrelated state.

# 33. Owned State

All resources created by the app must have a unique owner/session identity.

```text
trdpi_<session-id>
```

Cleanup only app-owned resources.

# 34. Failure Handling

Every backend change:

```text
snapshot
prepare
apply
verify
commit
```

Failure:

```text
rollback
verify-clean
```

Never leave a broken half-configured state intentionally.

# 35. Linux AppImage

Primary artifact:

```text
TR-DPI-<version>-x86_64.AppImage
```

Also optionally:
```text
.deb
.rpm
AUR
```

AppImage startup must perform capability detection.

If FUSE is unavailable, provide a graphical fallback rather than telling the user to run commands manually.

# 36. Windows

Primary artifact:

```text
TR-DPI-Setup-x64.exe
```

Use:
- UAC
- helper/service lifecycle
- clean uninstall
- signed artifacts

# 37. UI Copy

Normal users should see:

```text
Bağlantı hazırlanıyor...
Ağınız analiz ediliyor...
Uygun yöntem seçiliyor...
Bağlantı doğrulanıyor...
Koruma aktif.
```

Not:

```text
nfqws
iptables
nft
WinDivert
SNI
desync
```

unless Advanced/Diagnostics view is explicitly opened.

# 38. Agent Rule — Don't Ask User to Fix Linux Manually

If a command is required internally:

```text
DO NOT:
“terminalde sudo nft ... çalıştır”

DO:
“implement privileged helper command over typed IPC”
```

# 39. Agent Rule — Test on Multiple Distros

Before marking Linux support complete:

```text
Ubuntu
Debian
Arch
Fedora
Mint
Manjaro
```

at minimum.

Test both:
- systemd present
- non-systemd fallback where applicable

# 40. Agent Rule — Consumer Installer Experience

Fresh machine:

```text
download
open
approve access
start
```

Goal: no additional documentation needed for ordinary users.

# 41. Final Product Position

Do not market as:
“GUI for Zapret.”

Market as:

> “Türkiye'deki bağlantı sorunlarını otomatik analiz eden ve uygun yöntemi kendi seçen, Windows ve Linux için tek tık masaüstü ağ aracı.”

The underlying engines are implementation details.
