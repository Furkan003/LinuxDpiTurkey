# TR-DPI Adaptive

Türkiye ağlarındaki bağlantı engellerini **önce teşhis eden**, sonra uygun yöntemi uygulayan açık kaynak ağ aracı. Linux ve Windows.

VPN değil. Uzak sunucu yok, hesap yok, trafik başka bir yere yönlendirilmiyor.

> **Durum:** Linux'ta sahte paket motoru çalışıyor. Grafik arayüz ve otomatik profil seçimi henüz yok.

## Neden

Mevcut araçlar (GoodbyeDPI, zapret, ByeDPI) güçlü motorlar sunuyor ama kullanıcıya onlarca parametre bırakıyor. Bu proje önce ağını ölçüyor, ne tür bir müdahale olduğunu sınıflandırıyor, sonra ona göre davranıyor.

Fark şurada: "hangi flag'i deneyeyim" yerine "bağlantım neden bozuk" sorusuna cevap veriyor.

## Koruma (Linux)

Bütün uygulamalar kapsam içinde. Discord, Sober ve diğerlerinde **hiçbir ayar yapmana gerek yok.**

```bash
sudo trdpi
sudo trdpi --ttl 3
```

Durdurmak için Ctrl+C — kurallar otomatik geri alınır.

Nasıl çalışıyor: giden TLS ClientHello paketi yakalanır ve ondan önce **aynı sıra numarasını taşıyan, düşük TTL'li sahte bir kopya** gönderilir. Sahte paket araya giren inceleme donanımına ulaşır ama gerçek sunucuya varmadan yolda ölür. Donanım kararını sahte pakete bakarak verir; arkasından gelen gerçek paketi eşleştiremez.

Site açılmıyorsa `--ttl` değerini değiştirmeyi dene (3, 5, 7). Doğru değer, sana en yakın inceleme noktasının kaç adım uzakta olduğuna bağlıdır.

### Neden parçalama değil

Önce TLS akışını bölmeyi denedik. Türkiye'de ölçtüğümüz hatta **hiç işe yaramadı**: sabit konumdan bölme, SNI ortasından bölme ve hiç bölmeme aynı başarısızlık oranını verdi (8 denemede 4). Bu engel akışı bölerek aşılmıyor.

### Şeffaf yönlendirme

`sudo trdpi-koruma` parçalama motorunu sistem geneline uygular. Ölçtüğümüz hatta işe yaramadı; başka davranış sergileyen ağlar için duruyor.

Çıkışta kaç bağlantının geçtiğini ve kaçının parçalandığını yazar:

```
Bağlantı: 4 · parçalanan: 4 · başarısız: 0
```

`Bağlantı: 0` görüyorsan yönlendirme çalışmamış demektir.

**Kapsam dışı:** UDP trafiği. Yani QUIC ve oyunların gerçek zamanlı bağlantısı bu yöntemden geçmez.

### Bir şeyler ters giderse

Süreç düzgün kapanamazsa (`kill -9`, elektrik kesintisi) nftables kuralı yerinde kalır ve **tüm TCP:443 trafiği kopar.** Kurtarma:

```bash
sudo trdpi-koruma --temizle
```

Uygulama zaten her açılışta kendine ait kalıntı kuralları arayıp siler.

## Teşhis motoru

Ayrıcalık gerektirmez, sistemde hiçbir şeyi değiştirmez.

```bash
cargo run -p trdpi-diagnostics --example teshis
cargo run -p trdpi-diagnostics --example teshis -- discord.com www.instagram.com
```

```
discord.com  [ölçüm]
  OK   DnsIntegrity             -  healthy            5 adres
  OK   TcpConnect           21 ms  healthy
  OK   TlsHandshake         21 ms  healthy
```

Ayırt ettiği durumlar:

```
healthy  degraded  throttled  quic_blocked
dns_tampered  tcp_reset  tls_interference  timeout  unknown
```

`tls_interference` ile `timeout` arasındaki fark bu projede önemli: birincisi ClientHello yazıldıktan *sonra* gelen reset (Türkiye'de gözlenen tipik davranış), ikincisi yanıtsızlık. Bu ayrımı koruyabilmek için TLS handshake'i hazır kütüphane yerine elle ölçülüyor — `rustls` gibi kütüphaneler her iki durumu da tek bir "handshake failed"e indirger.

## Yerel proxy (Windows ve Linux)

Yönetici yetkisi istemez ama yalnızca kendisine yönlendirilen uygulamaları korur.

```bash
cargo run -p trdpi-proxy --bin trdpi-proxy -- --port 1080
```

Firefox: **Ayarlar → Ağ Ayarları → Elle proxy → SOCKS v5**, `127.0.0.1:1080`, *"SOCKS v5 kullanırken DNS'i proxy üzerinden çöz"* işaretli.

| Seçenek | Değer | Varsayılan |
|---|---|---|
| `--port` | dinlenecek port | 1080 |
| `--strateji` | `sni` \| `kapali` \| `sabit:<konum>` | `sni` |
| `--gecikme` | parçalar arası bekleme (ms) | 12 |

## Yapı

```
crates/
├─ core/          kanonik tipler ve sözleşmeler — I/O yok, platform kodu yok
├─ diagnostics/   ağ ölçümü — ayrıcalık gerektirmez
├─ proxy/         yerel SOCKS5 motoru — ayrıcalık gerektirmez
├─ transparent/   şeffaf yönlendirme (Linux) — nftables
└─ nfqueue/       sahte paket + TTL motoru (Linux) — NFQUEUE + ham soket
```

`crates/core` projenin tek normatif sözleşme kaynağıdır. `TR-DPI-Adaptive-*.md` dosyaları gerekçe ve arka plan belgeleridir; tip tanımı için normatif değildir.

## Tasarım kuralları

- **Yalnızca kendi objelerimize dokunuruz.** Oluşturulan her nftables tablosu oturum kimliğiyle etiketlenir. `docker0`, `ufw-*`, `firewalld` gibi yabancı objeler ne yedeklenir ne silinir — ve hiçbir komut `flush ruleset` üretmez.
- **Her sistem değişikliği snapshot + geri alma ile yapılır.** `Backend::rollback` snapshot alır; almayan bir imza kabul edilmez.
- **Motor çökerse internet kesilmemeli.** Kuyruk kuralı `bypass` bayrağıyla kurulur: dinleyen program yoksa paketler düşürülmez, olduğu gibi geçer.
- **Geri alma sırası önemlidir.** Önce nftables kuralı kaldırılır, sonra dinleyici kapatılır. Tersi olsaydı trafik var olmayan bir porta yönlenir ve ağ tamamen kopardı.
- **Ölçüm yokluğu sağlık kanıtı değildir.** Veri toplanamadıysa sonuç `unknown`, `healthy` değil.
- **Kapalı port sansür değildir.** Bağlantı reddi ve erişilemeyen yol `unknown` sayılır.
- **Yapamadığımız tekniği sessizce yok saymayız.** Kullanıcı alanı motorları sahte paket ve TTL tekniği uygulayamaz; bunları isteyen profil reddedilir. Sessizce yok saymak başarısızlığın yanlış sebebe atfedilmesine yol açardı.
- **`nft` komutuna argüman dizisi verilir**, kabuk dizesi değil. Dinamik değerler (tablo adı, portlar) alfanumerik olmaya zorlanır.
- **Kullanıcıya terminal komutu önerilmez.** Her hata durumunun arayüzde karşılığı vardır.
- **Karar distro adına değil yetenek tespitine dayanır.** `/etc/os-release` yalnızca gösterim içindir.

## Gizlilik

Telemetri yok. Ölçüm sonuçları hiçbir sunucuya gönderilmez.

Ölçüm hedefleri sabittir ve gezinme geçmişinden türetilmez; sonuçlarda trafik içeriği, payload veya tam URL saklanmaz.

Şunun farkında ol: **teşhis ölçümünün kendisi ağ üzerinde gözlemlenebilir.** Uygulama bilinen hedeflere istek atar ve bu, bağlantını sağlayan taraf için görünür bir izdir. Bu yüzden hedef listesi kısa tutulur ve ölçüm arka planda sürekli çalıştırılmaz.

## Geliştirme

Rust 1.82+ gerekir.

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

Testlerin tamamı gerçek ağ backend'i olmadan çalışır; ağ gerektiren tek şey `teshis` örneğidir. Linux'a özel kod WSL2 üzerinde de derlenip test edilebilir — WSL2 çekirdeği nftables ve NFQUEUE destekler.

## Yol haritası

- [x] Kanonik tip katmanı
- [x] Teşhis motoru (DNS / TCP / TLS)
- [x] Yerel proxy motoru + SNI parçalama
- [x] Şeffaf yönlendirme (Linux, nftables)
- [x] Yetim kural temizliği ve sinyal ile güvenli kapanış
- [x] Sahte paket + TTL motoru (NFQUEUE)
- [ ] Politika motoru — teşhis sonucundan otomatik profil seçimi
- [ ] QUIC erişilebilirlik ölçümü
- [ ] Grafik arayüz
- [ ] AppImage / deb / rpm paketleme
- [ ] Windows sistem geneli koruma

## Lisans

MIT. Bkz. [LICENSE](LICENSE).
