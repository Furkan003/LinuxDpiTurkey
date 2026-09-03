# TR-DPI Adaptive

Türkiye ağlarındaki bağlantı engellerini **önce teşhis eden**, sonra uygun yöntemi seçen açık kaynak masaüstü ağ aracı. Linux ve Windows.

VPN değil. Uzak sunucu yok, hesap yok, trafik başka bir yere yönlendirilmiyor.

> **Durum:** Geliştirme aşamasında. Teşhis motoru ve yerel proxy motoru çalışıyor ve kullanılabilir. Sistem geneli koruma (NFQUEUE) ve grafik arayüz henüz yok.

## Neden

Mevcut araçlar (GoodbyeDPI, zapret, ByeDPI) güçlü motorlar sunuyor ama kullanıcıya onlarca parametre bırakıyor. Bu proje bunun tersini yapıyor: **önce ağını ölçüyor**, ne tür bir müdahale olduğunu sınıflandırıyor, sonra ona uygun yöntemi seçiyor.

Fark şurada: "hangi flag'i deneyeyim" sorusu yerine "bağlantım neden bozuk" sorusuna cevap veriyor.

## Şu an çalışan

### Teşhis motoru

Ayrıcalık gerektirmez, sistemde hiçbir şeyi değiştirmez.

```bash
cargo run -p trdpi-diagnostics --example teshis
cargo run -p trdpi-diagnostics --example teshis -- discord.com www.instagram.com
```

Örnek çıktı:

```
discord.com  [ölçüm]
  OK   DnsIntegrity             -  healthy            5 adres
  OK   TcpConnect           21 ms  healthy
  OK   TlsHandshake         21 ms  healthy
```

Ölçtüğü ve ayırt ettiği durumlar:

```
healthy  degraded  throttled  quic_blocked
dns_tampered  tcp_reset  tls_interference  timeout  unknown
```

`tls_interference` ile `timeout` arasındaki fark bu projede önemli: birincisi ClientHello yazıldıktan *sonra* gelen reset (Türkiye'de gözlenen tipik davranış), ikincisi yanıtsızlık. Bu ayrımı koruyabilmek için TLS handshake'i hazır kütüphane yerine elle ölçülüyor — `rustls` gibi kütüphaneler her iki durumu da tek bir "handshake failed"e indirir.

### Yerel proxy motoru

Ayrıcalık gerektirmez. TLS ClientHello'yu SNI'ın ortasından bölerek gönderir.

```bash
cargo run -p trdpi-proxy --bin trdpi-proxy
cargo run -p trdpi-proxy --bin trdpi-proxy -- --port 1080 --strateji sni
```

Sonra tarayıcını `127.0.0.1:1080` SOCKS5 adresine yönlendir. Firefox'ta: **Ayarlar → Ağ Ayarları → Elle proxy → SOCKS v5**, ve *"SOCKS v5 kullanırken DNS'i proxy üzerinden çöz"* işaretli olsun.

Seçenekler:

| Seçenek | Değer | Varsayılan |
|---|---|---|
| `--port` | dinlenecek port | 1080 |
| `--strateji` | `sni` \| `kapali` \| `sabit:<konum>` | `sni` |
| `--gecikme` | parçalar arası bekleme (ms) | 12 |

**Kapsamı sınırlı:** yalnızca proxy'ye yönlendirilen uygulamalar etkilenir. Sistem geneli koruma NFQUEUE ister, o henüz yazılmadı.

**Yapamadıkları:** sahte paket, TTL oyunları, sıra dışı gönderim. Bunlar ham paket erişimi ister. Motor bunları isteyen bir profili sessizce yok saymaz — reddeder, çünkü sessizce yok saymak başarısızlığın yanlış sebebe atfedilmesine yol açar.

## Yapı

```
crates/
├─ core/          kanonik tipler ve sözleşmeler — I/O yok, platform kodu yok, unsafe yok
├─ diagnostics/   ağ ölçümü — ayrıcalık gerektirmez
└─ proxy/         yerel SOCKS5 motoru — ayrıcalık gerektirmez
```

`crates/core` projenin tek normatif sözleşme kaynağıdır. `TR-DPI-Adaptive-*.md` dosyaları gerekçe ve arka plan belgeleridir; tip tanımı için normatif değildir.

## Tasarım kuralları

- **GUI asla root/admin çalışmaz.** Ayrıcalık gereken işler ayrı bir yardımcıya gider.
- **Her sistem değişikliği snapshot + geri alma ile yapılır.** `Backend::rollback` snapshot alır; alamayan bir imza kabul edilmez.
- **Yalnızca kendi objelerimize dokunuruz.** Oluşturulan her sistem objesi oturum kimliğiyle etiketlenir; `docker0` veya `ufw-*` gibi yabancı objeler snapshot'a kaydedilemez.
- **Ölçüm yokluğu sağlık kanıtı değildir.** Veri toplanamadıysa sonuç `unknown`'dır, `healthy` değil.
- **Kapalı port sansür değildir.** Bağlantı reddi ve erişilemeyen yol `unknown` sayılır.
- **Kullanıcıya terminal komutu önerilmez.** Her hata durumunun kullanıcı arayüzünde karşılığı vardır.
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

Testlerin tamamı gerçek ağ backend'i olmadan çalışır. Ağ gerektiren tek şey `teshis` örneğidir.

## Yol haritası

- [x] Kanonik tip katmanı
- [x] Teşhis motoru (DNS / TCP / TLS)
- [x] Yerel proxy motoru + SNI parçalama
- [ ] Politika motoru — teşhisten profil seçimi
- [ ] QUIC erişilebilirlik ölçümü
- [ ] Linux NFQUEUE motoru + polkit yardımcısı
- [ ] Grafik arayüz
- [ ] AppImage / deb / rpm paketleme

## Lisans

MIT. Bkz. [LICENSE](LICENSE).
