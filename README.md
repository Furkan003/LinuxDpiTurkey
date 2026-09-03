# TR-DPI Adaptive

Türkiye ağlarındaki bağlantı engellerini **önce teşhis eden**, sonra uygun yöntemi uygulayan açık kaynak ağ aracı. Linux ve Windows.

VPN değil. Uzak sunucu yok, hesap yok, trafik başka bir yere yönlendirilmiyor.

> **Durum:** Linux'ta sistem geneli koruma çalışıyor. Grafik arayüz ve otomatik profil seçimi henüz yok.

## Neden

Mevcut araçlar (GoodbyeDPI, zapret, ByeDPI) güçlü motorlar sunuyor ama kullanıcıya onlarca parametre bırakıyor. Bu proje önce ağını ölçüyor, ne tür bir müdahale olduğunu sınıflandırıyor, sonra ona göre davranıyor.

Fark şurada: "hangi flag'i deneyeyim" yerine "bağlantım neden bozuk" sorusuna cevap veriyor.

## Sistem geneli koruma (Linux)

Bütün uygulamalar kapsam içinde. Discord, Sober ve diğerlerinde **hiçbir ayar yapmana gerek yok.**

```bash
sudo trdpi-koruma
```

Durdurmak için Ctrl+C — kurallar otomatik geri alınır.

Nasıl çalışıyor: nftables ile giden TCP:443 trafiği yerel bir dinleyiciye yönlendirilir, orada TLS ClientHello alan adının ortasından ikiye bölünerek iletilir. Böylece araya giren inceleme donanımı alan adını tek parçada göremez.

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
└─ transparent/   sistem geneli yönlendirme (Linux) — nftables
```

`crates/core` projenin tek normatif sözleşme kaynağıdır. `TR-DPI-Adaptive-*.md` dosyaları gerekçe ve arka plan belgeleridir; tip tanımı için normatif değildir.

## Tasarım kuralları

- **Yalnızca kendi objelerimize dokunuruz.** Oluşturulan her nftables tablosu oturum kimliğiyle etiketlenir. `docker0`, `ufw-*`, `firewalld` gibi yabancı objeler ne yedeklenir ne silinir — ve hiçbir komut `flush ruleset` üretmez.
- **Her sistem değişikliği snapshot + geri alma ile yapılır.** `Backend::rollback` snapshot alır; almayan bir imza kabul edilmez.
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
- [x] Sistem geneli koruma (Linux, nftables)
- [x] Yetim kural temizliği ve sinyal ile güvenli kapanış
- [ ] Politika motoru — teşhis sonucundan otomatik profil seçimi
- [ ] QUIC erişilebilirlik ölçümü
- [ ] Grafik arayüz
- [ ] AppImage / deb / rpm paketleme
- [ ] Windows sistem geneli koruma

## Lisans

MIT. Bkz. [LICENSE](LICENSE).
