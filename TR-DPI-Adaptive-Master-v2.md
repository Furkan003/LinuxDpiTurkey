# TR-DPI Adaptive — Master Project Specification v2

## Amaç

Windows `.exe` ve Linux `.AppImage` ile dağıtılan; kullanıcıdan terminal komutu, manuel DNS/proxy/nftables/iptables/systemd ayarı istemeyen; ağ davranışını otomatik teşhis edip uygun anti-DPI/backend stratejisini seçen modern masaüstü uygulaması.

## Referans projeler

- GoodbyeDPI
- GoodbyeDPI-Turkey
- Zapret
- Zapret2
- ByeDPI
- SpoofDPI
- SplitWire-Turkey
- GreenTunnel
- PowerTunnel
- sing-box

## Ana ürün tezi

```text
Existing projects = engines / techniques
Our product      = adaptive orchestration + UX + recovery
```

## Kullanıcı yolculuğu

```text
Download
  ↓
Open
  ↓
Capability Check
  ↓
Graphical Permission
  ↓
Baseline Diagnosis
  ↓
Backend Selection
  ↓
Profile Selection
  ↓
Apply
  ↓
Health Check
  ↓
Running
  ↓
Continuous Monitoring
  ↓
Automatic Recovery / Rollback
```

## Platform mimarisi

```text
                   Tauri GUI
                       |
                 Rust Orchestrator
                       |
           +-----------+-----------+
           |                       |
       Diagnostics             Policy Engine
           |                       |
           +-----------+-----------+
                       |
                 Backend Registry
          +------------+-------------+
          |            |             |
       Zapret2      GoodbyeDPI     Proxy
       Adapter        Adapter      Adapter
          |            |             |
          +------------+-------------+
                       |
               Privilege Broker
                 /           \
              Windows       Linux
             UAC/helper    polkit/helper
```

## Linux ana prensibi

**Kullanıcı terminal görmeyecek.**

Uygulama:
- capability discovery
- privileged helper
- nftables/NFQUEUE lifecycle
- optional DNS handling
- proxy fallback
- autostart
- cleanup
- rollback

işlerini kendisi yönetir.

## Linux için “her distro” stratejisi

Distro adına değil capability'ye göre:

```text
kernel
nftables
NFQUEUE
polkit
init system
FUSE
network stack
```

kontrol edilir.

Ana hedefler:
- Ubuntu
- Debian
- Arch
- Fedora
- Mint
- Manjaro

Dağıtım:
- AppImage
- deb
- rpm
- AUR

## Windows

- x64 `.exe`
- UAC/helper
- service
- auto-start
- signed installer

## En güçlü özelliğimiz

```text
AUTO DIAGNOSIS
       +
AUTO BACKEND
       +
AUTO PROFILE
       +
HEALTH MONITOR
       +
ROLLBACK
```

## Teknik karar

MVP'de sıfırdan yeni bir packet manipulation stack yazma.

Önce:
- mevcut açık kaynak motorları adapter arkasına al,
- orchestrator ve UX'i kendin geliştir,
- daha sonra ihtiyaç olan fonksiyonları native core'a taşı.

## Güvenlik

- non-root GUI
- typed IPC
- no arbitrary shell
- minimal helper permissions
- signed updates
- sanitized logs
- local-first privacy
- owned-state cleanup
- transaction/rollback

## MVP

### Windows
- installer
- helper
- automatic profile
- diagnostics
- start/stop
- rollback

### Linux
- AppImage
- graphical privilege request
- capability detection
- NFQUEUE/nftables adapter
- proxy fallback
- diagnostics
- start/stop
- rollback

## V1

- adaptive ranking
- network fingerprint
- background health monitor
- ISP/ASN context as one signal, not sole decision
- import/export profiles
- signed remote profile manifest

## V2

- community strategy registry
- privacy-preserving opt-in aggregate statistics
- better global country profiles

## Kaynaklar

### Türkiye / saha
- https://github.com/cagritaskn/GoodbyeDPI-Turkey
- https://github.com/cagritaskn/SplitWire-Turkey
- https://explorer.ooni.org/
- https://ifade.org.tr/en/reports/engelliweb-2025/

### Motorlar
- https://github.com/ValdikSS/GoodbyeDPI
- https://github.com/bol-van/zapret
- https://github.com/bol-van/zapret2
- https://github.com/xvzc/spoofdpi
- https://github.com/SagerNet/sing-box

### Packaging
- https://v2.tauri.app/distribute/
- https://v2.tauri.app/distribute/appimage/
