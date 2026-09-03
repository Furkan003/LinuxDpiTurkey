# TR-DPI Adaptive — Doküman Denetim Raporu

**Denetlenen dosyalar:** Master-v2, Pazar-Arastirmasi-v2, Teknik-Sartname-v2, Vibe-Coding-Plan-v2 (toplam 4.122 satır)
**Denetim tarihi:** 3 Eylül 2026
**Kapsam:** İç tutarlılık, teknik uygulanabilirlik, eksik kararlar. Kod yazılmadı.

Kısaltmalar: **M** = Master · **P** = Pazar Araştırması · **T** = Teknik Şartname · **V** = Vibe Coding Plan

---

## Genel değerlendirme

Ürün tezi sağlam. "Motorlar zaten var, eksik olan orkestrasyon + UX + rollback" tespiti doğru ve savunulabilir bir konumlandırma. Sansür davranışını cihaz markası yerine ölçülebilir davranış üzerinden modellemek (P §38) doğru mühendislik kararı.

Ancak dokümanlar **bu haliyle bir kodlama ajanına verilemez.** Sebep: aynı veri yapısı, aynı trait, aynı state machine ve aynı klasör yapısı dört dosyada birbiriyle uyumsuz biçimlerde tanımlanmış. Bir ajan hangisini seçeceğine rastgele karar verir, ikinci ajan başka birini seçer, entegrasyonda çakışır.

Ayrıca ürünün temel vaadini (Linux'ta sıfır terminal) doğrudan geçersiz kılan bir mantık hatası ve ürünün en önemli metriğini ölçmeyi imkânsız kılan bir çelişki var.

**Bulgu sayısı:** 6 blocker · 9 yüksek · 11 orta · 8 doğrulanmalı · 10 eksik

---

# A. BLOCKER — kod yazmadan önce çözülmeli

## A1. Tek bir `Profile` yapısı yok, dört farklı tanım var

| Kaynak | Alanlar |
|---|---|
| P §11 (JSON) | `id, name, risk, protocols{dns,tcp,tls,quic}, strategy{fragment, fake_packets, ttl, header_normalization}, health{success_threshold, latency_penalty, packet_loss_penalty}` |
| T §5 (Rust) | `id, name, platform, protocols, strategy{fragmentation, fake_traffic, ttl, header_strategy, quic}, health` |
| V Phase 6 | `id, name, description, risk, supported backends, protocol policy, health threshold` |
| P §37 | profil sadece `profileId` + `score` olarak geçiyor |

Somut uyuşmazlıklar:

- `risk` JSON'da var, Rust struct'ta yok. `platform` Rust'ta var, JSON'da yok.
- `description` ve `supported_backends` yalnız V Phase 6'da var, hiçbir şemada yok.
- Aynı kavram üç isimle: `fragment` / `fragmentation`, `fake_packets` / `fake_traffic`, `header_normalization` / `header_strategy`.
- `quic` P §11'de **protocols** altında, T §5'te **strategy** altında. Bunlar farklı semantik.
- P §36 Kural 10 "versioned local profile store" istiyor ama hiçbir şemada `version` alanı yok.
- T §5'te `platform: String` — stringly-typed; enum olmalı.

**Bu, ürünün en merkezi veri yapısı.** Tek kanonik şema yazılıp diğer üç tanım silinmeli.

## A2. Üç farklı `Backend` trait'i — ve T §3'teki yanlış olan

| Kaynak | İmza |
|---|---|
| P §10.3 `PacketBackend` | `capabilities, prepare(&mut), apply_profile(&mut), stop, rollback` |
| T §3 `NetworkBackend` | `name, capabilities, prepare(&self), start(&Profile), stop, rollback(&self)` |
| P §67 `Backend` | `id, capabilities, probe, prepare() -> Snapshot, apply, verify, stop, rollback(Snapshot)` |

Kritik nokta: **T §3'teki `rollback(&self)` snapshot parametresi almıyor.** Bu, P §60 ve T §8'de tarif edilen `snapshot → apply → verify → commit / restore-snapshot` transaction modelini uygulamayı imkânsız kılıyor — geri alınacak durum trait'e hiç girmiyor.

Ve dosya "Teknik Şartname" adını taşıdığı için bir ajanın implement edeceği ilk trait büyük olasılıkla **yanlış olanı** olacak. P §67 doğru olan; T §3 onunla değiştirilmeli.

## A3. State machine üç kez, üç farklı sözlükle — ve IPC sözleşmesi UI metnini süremiyor

- **P §8 (mermaid):** Detecting → Baseline → Diagnosis → StrategySelect → CandidateTest → Healthy → Monitoring → Recovery
- **T §14:** STOPPED → STARTING → DIAGNOSING → SELECTING → APPLYING → VERIFYING → RUNNING / ROLLBACK → NEXT_PROFILE
- **P §27 IPC `EngineStatus`:** `stopped | starting | running | degraded | recovering | error`

`EngineStatus` enum'unda `diagnosing`, `selecting`, `applying`, `verifying` **yok.**

Doğrudan sonucu: V §37 ve T §31'de zorunlu tutulan kullanıcı metni

```
Bağlantı hazırlanıyor...
Ağınız analiz ediliyor...
Uygun yöntem seçiliyor...
Bağlantı doğrulanıyor...
Koruma aktif.
```

**belirtilen IPC sözleşmesiyle üretilemez.** Beş ayrı ekran durumunun hepsi tek bir `"starting"` değerine düşüyor. Bu bir isimlendirme tartışması değil, çalışmayan bir arayüz.

## A4. FUSE fallback mantıksal olarak imkânsız

P §40 ve P §68: FUSE yoksa kullanıcıya terminal komutu yazdırma, **grafiksel** fallback sun —

```
Bu Linux sisteminde AppImage mount özelliği kullanılamıyor.
[ Uygulama modunda çalıştır ]
```

FUSE yoksa AppImage **mount edilemez, dolayısıyla GUI hiç başlamaz.** O butonu gösterecek pencere ortada yoktur; standart AppImage runtime hatayı stderr'e basıp çıkar. Bu ekran hiçbir koşulda görünemez.

Bu, ürünün birinci vaadinin (Linux'ta sıfır terminal) tam olarak en çok ihtiyaç duyulduğu anda çöktüğü nokta. Ve teorik bir senaryo değil: **Ubuntu 22.04+ ve türevlerinde `libfuse2` varsayılan kurulu gelmiyor**, yani hedef kitlenin büyük bölümü bu duruma düşer.

Gerçek çözüm seçenekleri (dokümanda hiçbiri yok):

1. FUSE gerektirmeyen statik AppImage runtime kullanmak (self-extracting),
2. `.deb`/`.rpm`'i Tier 1'e çıkarıp AppImage'i Tier 2 yapmak,
3. AppImage'i sarmalayan küçük statik launcher göndermek.

Karar verilmeli; mevcut metin uygulanamaz.

## A5. "NO TELEMETRY" varsayılanı ile ürünün birinci metriği çelişiyor

- P §23: varsayılan **NO TELEMETRY**; test sonuçları, hata logları sunucuya gitmez.
- P §49: *"En önemli metrik: İlk çalıştırmadan başarılı bağlantıya geçen kullanıcı oranı."*
- P §32: `install → first successful connection`, `7-day retention`, `crash-free sessions`.

Telemetri kapalıyken bu metriklerin hiçbiri ölçülemez. Doküman, ölçülemeyecek bir metriği "en önemli" ilan ediyor.

Çözülebilir bir çelişki (opt-in ölçüm, kontrollü beta kohortu, ya da metriği değiştirmek) — ama çözülmeden ürün stratejisi hatalı bir temele oturuyor. V2'ye ertelenen "opt-in aggregate telemetry" bunu MVP'de karşılamıyor.

## A6. İki uyumsuz repo yapısı

- **P §35:** `trdpi/` altında `apps/desktop`, `crates/{core,diagnostics,policy,profiles,platform,dns,proxy,packet,storage,telemetry}`, `platform/`, `profiles/`, `packaging/`, `tests/` — Cargo workspace.
- **T §2:** `src-tauri/src/{commands,engine,diagnostics,policy,profiles,platform,dns,health,firewall,storage,security}` + `src/` — tek crate.

Bunlar birleştirilemez. T §2 yapısı ayrıca V §21'in "her şey gerçek ağ backend'i olmadan unit-test edilebilmeli" şartını zorlaştırıyor; ayrı crate'ler bunu doğal biçimde sağlar.

İlk `cargo new` komutundan önce karar verilmesi gereken tek şey bu.

---

# B. YÜKSEK

## B1. "backend" kelimesi iki farklı şeyi kastediyor

- P §27: `backend: "windivert" | "nfqueue" | "proxy"` → bu bir **mekanizma**
- T §29 / V §28 / M: `zapret2, goodbyedpi, byedpi, proxy, dns` → bu bir **motor**

`zapret2` motoru hem `nfqueue` hem `windivert` mekanizması üzerinde çalışabilir. Tek alanda birleştirilemezler. `mechanism` ve `engine` olarak ayrılmalı; aksi halde registry ve IPC sözleşmesi ilk gerçek adapter'da kırılır.

## B2. İki uyumsuz skorlama modeli

- P §15.2: `score = 0.30·availability + 0.20·handshake + 0.15·http + 0.10·quic + 0.10·low_latency + 0.10·low_reset + 0.05·dns_integrity` (ağırlıklar toplamı 1.00 ✓)
- P §11: profil içinde `latency_penalty: 0.20`, `packet_loss_penalty: 0.30`

İkinci gruptaki "penalty" değerleri birinci formülde **hiç yok.** Ayrıca `latency_penalty: 0.20` bir ağırlık mı, eşik mi, çarpan mı — tanımsız. `packet_loss` §15.2 formülünde geçmiyor ama P §29 feature listesinde var.

Tek skorlama fonksiyonu tanımlanmalı; teşhis skoru ile profil-aday skorunun aynı fonksiyon mu farklı fonksiyonlar mı olduğu netleşmeli.

## B3. Durum sınıflandırma enum'u üç farklı üyelikle

| Kaynak | Üyeler |
|---|---|
| P §3.3 | `PASS, DEGRADED, THROTTLED, DNS_TAMPER, TCP_RESET, TLS_INTERFERENCE, TIMEOUT` |
| P §15.3 | `HEALTHY, DEGRADED, DNS_TAMPERED, TCP_RESET, TLS_INTERFERENCE, THROTTLED, QUIC_BLOCKED, UNKNOWN` |
| V Phase 4 | P §15.3 ile aynı (lowercase) |

`PASS` vs `HEALTHY`, `DNS_TAMPER` vs `DNS_TAMPERED`; `TIMEOUT` yalnız birinde, `QUIC_BLOCKED`/`UNKNOWN` diğerinde. Serde ile serialize edilecek bir enum için bu doğrudan runtime hatası üretir.

## B4. "Wrapper backend" ile "no arbitrary shell execution" arasındaki boşluk

- P §56 seçenek C: mevcut motorların **process lifecycle'ını** uygulama yönetir → yani `nfqws` benzeri binary'ler CLI parametreleriyle çalıştırılır.
- P §22.1: *"no arbitrary shell execution from renderer"*
- T §25: *"Broker arbitrary shell komutu kabul etmemeli."*

Bunlar teknik olarak çelişmiyor (sabit bir binary'yi doğrulanmış argv ile çalıştırmak ≠ arbitrary shell) ama **dokümanlar bu ayrımı hiç kurmuyor.** Ve P §56, MVP için tam olarak C'yi öneriyor.

Eksik olan ve yazılması gereken kurallar:

- yalnız `argv` dizisi, asla shell string interpolation yok,
- backend başına allowlist'lenmiş flag şeması,
- pinlenmiş sürüm + checksum doğrulaması (T §35 istiyor ama broker yüzeyine bağlanmamış),
- profil verisinden CLI parametresi üretilirken tam validasyon.

Bu yazılmazsa "profil → CLI flag" dönüşümü doğrudan bir komut enjeksiyon yüzeyi olur.

## B5. Updater, kendi güvenlik kuralını ihlal ediyor

- P §22.1: *"no remote executable download"*
- T §17: updater imzalı artifact indirip kuruyor; IPC'de `check_update`, `install_update` var.

İkincisi tanımı gereği uzaktan çalıştırılabilir kod indirmek. Kural şöyle yeniden yazılmalı: *"imzalı updater kanalı dışında hiçbir uzak kod indirilmez ve çalıştırılmaz."* Şu haliyle kural kendi mimarisini yasaklıyor.

## B6. Güncelleme ve profil dağıtım kanalının sansüre dayanıklılığı hiç ele alınmamış

Ürün, engellemenin yaygın olduğu bir ağda çalışacak. Ama:

- P V1: "signed remote profile manifest"
- T §17: update manifest
- P §39: dağıtım "GitHub Release / CDN"

**Bu kanalların kendisi engellenirse ne olur?** Dokümanların hiçbir yerinde yok. Ürünün tam olarak ihtiyaç duyulduğu anda güncellenememesi demek. Sansür karşıtı bir araç için birinci sınıf bir tasarım sorunu, sonradan eklenecek bir özellik değil.

En az şunlar kararlaştırılmalı: birden fazla mirror, manifest'in taşıma katmanından bağımsız imzalanması, offline profil import (V1'de zaten "import/export" var — ama sansür yanıtı olarak konumlandırılmamış).

## B7. Windows sürücü imzalama gerçeği eksik

P §45 yalnız **antivirüs false positive** riskini yazıyor. Asıl engel bu değil:

- WinDivert bir **kernel driver** (`WinDivert64.sys`) içerir.
- Modern Windows'ta Secure Boot / HVCI (Memory Integrity) altında yüklenebilmesi için sürücünün EV sertifikası + Microsoft attestation imzası taşıması gerekir.
- Üçüncü tarafın sürücüsünü **yeniden imzalayamazsınız**; onların imzalı binary'sini dağıtırsınız — bu da sürüm pinleme ve tedarik zinciri sorumluluğu getirir.
- HVCI açık makinelerde bazı sürücüler yüklenmez; bu "kurulum bitti ama motor başlamıyor" hatası olarak görünür ve dokümanda bu hata durumu tanımlı değil.
- EV kod imzalama sertifikası kimlik doğrulama + donanım token süreci gerektirir; P §47'de "Hafta 4: signing" olarak geçmesi bu sürecin süresini ciddi biçimde küçümsüyor.

## B8. Portable modda ayrıcalıklı durumun nerede yaşadığı tanımsız

- P §17: `"firewall_snapshot": "/var/lib/trdpi/snapshots/....json"`
- P §69: **Portable** mod — AppImage doğrudan çalışır, kurulum yok.
- M: GUI root değil.

`/var/lib/trdpi/` yazmak root gerektirir. Portable modda kurulum yapılmamışsa bu dizin yoktur. Snapshot'ı kim, nereye yazar? Helper mi? Helper portable modda nasıl kalıcı olur?

Ayrıca T §16 snapshot'ları **SQLite tablosu** olarak listeliyor, P §17 ise **dosya yolu** veriyor. İki farklı depolama yeri.

Buna bağlı ikinci sorun: T §34 crash recovery için watchdog + session lease + heartbeat istiyor. Bu pratikte kalıcı bir daemon demek — "kurulum yapmadan çalışan portable AppImage" ile doğrudan gerilim içinde. Çözülmemiş.

## B9. Dört farklı MVP tanımı

1. **M — MVP** (ayrı Windows ve Linux listeleri)
2. **P §33 — MVP** (11 madde)
3. **P §48 — MVP Definition of Done** (14 madde)
4. **V §24 — Definition of success / public alpha** (12 madde)

Aralarında gerçek kapsam farkları var: P §33'te Linux backend seçimi hiç geçmiyor, M'de NFQUEUE adapter + proxy fallback MVP'de; V §24 crash recovery ve signed release istiyor, P §33 istemiyor.

Tek bir "MVP Definition of Done" bırakılıp diğer üçü ona referans vermeli.

---

# C. ORTA

## C1. nftables isimlendirmesi UUID ile çalışmaz

T §27 ve V §33: `trdpi_<session-id>`, `session=<uuid>`. UUID tire içerir; nft identifier'larında tire tırnaksız kullanılamaz. Session id'ler tiresiz (hex) üretilmeli. Küçük ama ilk gerçek `nft add table` çağrısında patlar.

## C2. Canlı olay kanalı (event stream) hiçbir yerde tanımlı değil

T §9 IPC allowlist'i tamamen request/response. Ama T §31'in "Starting → Diagnosing → Applying → Checking → Protected" akışı ile Monitoring durumu, push edilen olay gerektirir. Tauri'nin event sistemi dokümanlarda hiç geçmiyor. `get_engine_status` polling'i ile bu UX zayıf olur.

## C3. Broker RPC yüzeyi eksik

T §25: `prepare_backend, apply_network_state, verify_network_state, rollback_network_state, install_autostart, remove_autostart`.

Eksikler:

- `stop` / graceful teardown (rollback ile aynı şey değil),
- `get_owned_state` — T §34'ün startup orphan cleanup'ı bunsuz yapılamaz,
- `heartbeat` / lease yenileme (T §34 istiyor, RPC'de yok),
- helper sürüm sorgusu — P §36 Kural 8 GUI'den bağımsız sürüm kontrolü istiyor.

## C4. IPC allowlist'i ürünün kendi gereksinimlerini karşılamıyor

T §9'da yok ama başka yerlerde zorunlu: autostart aç/kapa (V1 "service mode"), profil import/export (V1), ayar okuma/yazma (T §18 Settings ekranı), uninstall/cleanup akışı (T §33).

## C5. Capability struct'ı üç farklı isimlendirmeyle

T §4 `BackendCapabilities` (`packet_interception`, `transparent_proxy`…), T §26 `LinuxCapabilities` (`nftables`, `nfqueue`…), V Phase 7 (`supports_nfqueue`, `supports_nftables`…). `supports_` öneki bazılarında var bazılarında yok; alan kümeleri örtüşüyor ama eşit değil.

## C6. SQLite şeması iki dosyada farklı

P §28: 3 tablo, DDL ile. T §16: 6 tablo (`settings`, `snapshots`, `updates` eklenmiş), DDL yok. Ayrıca hiçbir tabloda `schema_version` / migration stratejisi yok.

## C7. Aynı anda iki instance çalışması ele alınmamış

AppImage'in iki kez açılması, ya da autostart servisi + manuel açılış. Firewall state ownership'i olan bir uygulamada bu veri bozulması demek. Single-instance lock hiçbir dokümanda geçmiyor.

## C8. IPv6 fingerprint'te var, politikada yok

P §29 feature listesinde `ipv6_available` var ama aynı bölümdeki hiçbir kural onu kullanmıyor. S0–S5 strateji sınıfları (P §12) IPv4 merkezli anlatılmış. T §20 test matrisinde "IPv6 only" ve "dual-stack" test edilecek ama ne yapılacağı tanımsız.

## C9. Health monitor parametreleri sayısız

V Phase 9: cooldown, hysteresis, maximum strategy switches, circuit breaker — hepsi doğru kavramlar ama **hiçbirine değer verilmemiş.** Probe aralığı da hiçbir yerde yok. P §31 KPI tablosunda monitoring maliyeti yok.

## C10. Teşhis testleri kullanıcı için gözlemlenebilir trafik üretiyor

P §15.1 test paketi "known-block-like domain" içeriyor. Yani uygulama, kullanıcının bağlantısından **bilinen engelli kaynaklara düzenli olarak istek atacak.** Bu, ISP tarafından gözlemlenebilir bir imzadır. P §23 gizlilik modeli yalnız "sunucuya ne gönderilmez"i tartışıyor; **yerel probing'in kendisinin gözlemlenebilir olduğu** hiç ele alınmamış. Bu araç sınıfı için ciddi bir kullanıcı güvenliği boşluğu.

## C11. Yerel veri saklama süresi tanımsız

P §28 `diagnostics` tablosu hangi siteye erişimin başarısız olduğunu yerelde biriktirir. P §23 "local-first privacy" diyor ama **retention/purge politikası yok.** Adli inceleme senaryosu düşünülürse bu tablo hassas. En azından varsayılan bir saklama süresi ve "geçmişi temizle" eylemi gerekir.

---

# D. DOĞRULANMASI GEREKEN İDDİALAR

Bunları harici kaynaktan doğrulamadım; dokümanlarda kaynak gösterilmiş ama iç tutarsızlık veya çürüme riski taşıyorlar.

## D1. Engelleme sayıları kendi içinde tutmuyor

P §2.2'deki yıllık yeni engelleme sayıları ile aynı bölümdeki kümülatif tablonun farkları uyuşmuyor:

| | Doküman "yeni" der | Kümülatif tablodan fark |
|---|---:|---:|
| 2025 | 232.441 | 1.505.484 − 1.264.506 = **240.978** |
| 2024 | 314.843 | 1.264.506 − 953.415 = **311.091** |

İki yönde de sapıyor (+8.537 / −3.752). Muhtemelen İFÖD farklı sayım yöntemleri kullanıyor (karar sayısı vs. tekilleştirilmiş domain, kaldırılan engeller vb.) — ama doküman bunları yan yana **tutarlıymış gibi** sunuyor. Açıklayıcı dipnot şart; yoksa raporun sayısal güvenilirliği ilk okuyan tarafından sorgulanır.

## D2. StatCounter kaynağı ile veri uyuşmuyor

P §2.4 "2026'nın ilk yarısı" ve "Haziran 2026" verisi veriyor ama URL `.../desktop-/turkey/2025`. URL'de ayrıca `desktop-/` yazım hatası var. Ya URL ya tarih yanlış.

Ek olarak yüzdeler toplamı: 69,58 + 4,93 + 4,57 + 0,04 + 16,21 = **%95,33.** Eksik %4,67 açıklanmamış; liste tammış gibi sunulmuş.

## D3. Discord tarihi ile kaynak etiketi uyuşmuyor

P §4 matrisi "08.10.2024–" diyor, atıf verilen OONI finding slug'ı `2025-turkiye-blocked-discord`. Biri düzeltilmeli.

## D4. GitHub star sayıları

GoodbyeDPI ~28,6k, Zapret2 ~5,3k, SpoofDPI ~5,0k, sing-box ~34,3k. Bu sayılar sürekli değişir ve "marka bilinirliği" kanıtı olarak zayıf bir metrik. Ya ölçüm tarihi eklenmeli ya da rekabet analizinden çıkarılmalı.

## D5. Üçüncü taraf lisansları — ürün modelini belirleyecek kadar kritik, ve hiç incelenmemiş

P §56 seçenek B doğrudan "upstream motorun binary/library olarak paketlenmesi"ni öneriyor; P §42 ise ücretli Supporter/Business katmanları öneriyor. Bu ikisinin birlikte mümkün olup olmadığı **tamamen lisansa bağlı** ve dokümanların hiçbirinde tek bir lisans adı geçmiyor.

Özellikle riskli olan: WinDivert'ın LGPL/GPL ailesinde olduğu ve sing-box'ın GPLv3 olduğu biliniyor — **bunu bu denetimde doğrulamadım, doğrulanması gerekiyor.** GPL ailesindeki bir bileşeni gömmek, kapalı kaynak ücretli bir katmanla ciddi biçimde çelişebilir.

T §35 "lisans doğrula" diyor ama bunu bir *implementasyon adımı* olarak listeliyor — oysa bu, ticari model kararından **önce** gelmesi gereken bir girdi.

## D6. Ürünün kendi lisansı hiçbir yerde yazmıyor

P §42 "çekirdek engine'i açık kaynak tutmak daha mantıklı **olabilir**" diyor ve karar vermiyor. Bu karar verilmeden D5'teki analiz de yapılamaz.

## D7. Tauri AppImage'in "her distro" kapsaması abartılı

P §18.1 AppImage'i "bağımlılıkların büyük bölümünü paketler" diye tanıtıyor. Tauri AppImage'leri WebKitGTK'ya bağlı ve glibc sürümüne duyarlıdır; build makinesinden eski glibc'li sistemlerde çalışmazlar. P §19 capability matrisinde "WebKit runtime" probe'u olması doğru — ama P §41'in 10 distroluk listesi bu kısıt yazılmadan verilmiş.

## D8. ARM64 hiç yok

Tüm artifact isimleri `x86_64` / `x64`. Windows ARM64 ve Linux aarch64 dokümanların hiçbirinde geçmiyor — kasıtlı kapsam dışı bırakma mı, gözden kaçma mı belli değil. Kapsam dışıysa M ve V §35'te açıkça yazılmalı (macOS için P §70'te yazıldığı gibi).

---

# E. TAMAMEN EKSİK OLANLAR

1. **Ürünün lisansı** (D6).
2. **Tehdit modeli.** Rakip kim, hangi yeteneklere sahip, uygulamanın kendisi hedef alınırsa ne olur. Sansür karşıtı bir üründe bu birinci bölüm olmalı.
3. **Güncelleme/profil kanalının engellenmesi senaryosu** (B6).
4. **Yerel veri saklama süresi ve silme** (C11).
5. **Kullanıcı probing'inin gözlemlenebilirliği** (C10).
6. **Hata taksonomisi.** Yalnızca polkit reddi için kullanıcı metni var (T §32). Helper çöktü, backend başlamadı, sürücü yüklenmedi (HVCI), rollback başarısız, ağ tamamen koptu — hiçbiri tanımlı değil. Bir uygulamada en çok yazılacak metin budur.
7. **Rollback'in kendisi başarısız olursa ne olacağı.** T §8 "cleanup başarısızsa kullanıcıya network recovery ekranı göster" diyor — o ekranın ne yaptığı tanımsız. Kullanıcının ağı bozuk durumda ve terminal kullanamıyor.
8. **Schema migration** (C6).
9. **Single instance** (C7).
10. **Ticari model ile hukuki risk arasındaki gerilim.** P §42 "Business: merkezi policy, organization profiles, managed deployment" öneriyor. Türkiye'de kurumlara sansür aşma aracı **satmak**, açık kaynak yayınlamaktan hukuken tamamen farklı bir pozisyon. P §45 hukuki riski yalnız 5651 ve BTK üzerinden genel olarak anıyor, bu ayrımı hiç kurmuyor. Dokümanın kendi kapsam notu hukukçu incelemesine gönderiyor — doğru; ama o incelemeye giderken bu iki bölümün çeliştiği not düşülmeli.

---

# F. GERÇEKÇİLİK: 30 GÜNLÜK PLAN

P §47 dört haftaya şunları sığdırıyor: repo + Tauri kabuk + UI + Rust orchestrator + iki platform build + iki ayrı ayrıcalıklı helper + packet backend soyutlaması + DNS teşhis + strateji motoru + profiller + rollback + health monitor + QUIC testi + paketleme + imzalama + updater + crash recovery + dokümantasyon + release CI + kontrollü ağ laboratuvarı.

Tek başına "polkit helper + transaction/rollback + doğrulanmış temiz durum" birkaç haftalık iş. EV kod imzalama sertifikası edinme süreci (B7) takvim olarak haftalar sürebilir ve mühendislikle paralelleştirilemez.

Aynı zamanda P §48, MVP'nin "tamam" sayılması için Ubuntu/Debian/Arch üzerinde test + crash recovery + code signing pipeline şart koşuyor.

Bu plan küçük bir ekip için gerçekçi değil. Takvim yeniden yazılmalı; aksi halde ilk iki haftada plana olan güven kaybolur ve kalite kısıtları (rollback, imzalama, test matrisi) ilk feda edilenler olur — ki bunlar tam olarak ürünün farklılaşma iddiası.

Not: P §47'nin "Hafta 4: signing" maddesi, sertifika tedarikinin **Hafta 0'da** başlaması gerektiğini gizliyor.

---

# G. ÖNERİLEN DÜZELTME SIRASI

Kod yazmadan önce, bu sırayla:

**1. Karar ver (kod yok, sadece karar):**

- Ürün lisansı (D6) → sonra üçüncü taraf lisans analizi (D5) → sonra ticari modelin mümkün olup olmadığı (P §42)
- Repo yapısı: workspace mı, tek crate mi (A6)
- FUSE stratejisi: statik runtime mı, deb/rpm Tier 1 mi (A4)
- Telemetri/ölçüm: birinci metriği nasıl ölçeceksin (A5)

**2. Tek kanonik sözleşme dosyası yaz.** Dört dokümandaki tüm tip tanımlarını silip tek bir kaynak oluştur (`CONTRACTS.md` ya da doğrudan `crates/core` içinde Rust tipleri):

- `Profile` (A1)
- `Backend` trait'i, snapshot'lı rollback ile (A2)
- `EngineState` — beş ara durumu içerecek şekilde (A3)
- `Classification` enum'u (B3)
- `Capabilities` (C5)
- `mechanism` vs `engine` ayrımı (B1)
- skorlama fonksiyonu (B2)
- IPC allowlist + event kanalı (C2, C4)
- Broker RPC yüzeyi (C3)

**3. Eksik bölümleri yaz:** tehdit modeli, hata taksonomisi, veri saklama politikası, kanal dayanıklılığı.

**4. Takvimi yeniden yaz** (F), sertifika tedarikini Hafta 0'a al.

**5. Dört MVP tanımını teke indir** (B9).

Bunlar bitmeden bir kodlama ajanına iş verilirse, üretilen kodun büyük bölümü sözleşme netleştiğinde atılacak.
