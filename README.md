# TR-DPI Adaptive

Türkiye ağlarındaki bağlantı engellerini **önce teşhis eden**, sonra uygun yöntemi uygulayan açık kaynak ağ aracı. Linux ve Windows.

VPN değil. Uzak sunucu yok, hesap yok, trafik başka bir yere yönlendirilmiyor.

> **Durum:** Ubuntu 24.04 üzerinde gerçek bir Türkiye hattında ölçülüp doğrulandı. Grafik arayüz henüz yok.

## Neden

Mevcut araçlar (GoodbyeDPI, zapret, ByeDPI) güçlü motorlar sunuyor ama kullanıcıya onlarca parametre bırakıyor. Bu proje önce ağını ölçüyor, ne tür bir müdahale olduğunu sınıflandırıyor, sonra ona göre davranıyor.

Fark şurada: "hangi flag'i deneyeyim" yerine "bağlantım neden bozuk" sorusuna cevap veriyor.

## Kullanım

Tek komut. Ölçer, gerekeni düzeltir, korur:

```bash
sudo trdpi
```

| Komut | Ne yapar |
|---|---|
| `sudo trdpi` | ölç, düzelt, koru |
| `trdpi --olc` | yalnızca ölç (yetki istemez) |
| `sudo trdpi --sure 600` | 10 dakika sonra kendiliğinden geri al |
| `sudo trdpi --durdur` | çalışan kopyaları durdur |
| `sudo trdpi --geri` | yapılan her şeyi geri al |

## Ölçülen sonuç

Gerçek bir Türkiye hattında (Ubuntu 24.04), 15'er deneme:

| | discord.com | roblox.com |
|---|---|---|
| Hiçbir şey yok | 0/15 | 0/15 |
| Sadece adres düzeltmesi | 8/15 | 7/15 |
| **Adres düzeltmesi + yeniden deneme** | **14/15** | **15/15** |
| Sadece adres düzeltmesi (kontrol) | 7/15 | 8/15 |

Motor kapatılıp tekrar ölçüldüğünde taban aynı yere döndü; yani fark zamanla değil yöntemle geldi.

## İki katmanlı engel, iki katmanlı çözüm

**1. Adres çözümlemesine müdahale.** Sistem, engellenen alan adları için `195.175.254.2` döndürüyor — OONI ölçümlerinde Türkiye'de sansür yanıtı olarak belgelenen adres. O adrese hiçbir kapıdan ulaşılamıyor.

Basit görünen çözüm işe yaramıyor: standart kapıdaki dış çözümleyicilerin tamamı kapalı. Çalışan tek yol standart dışı kapıdan sormak. Program adayları **deneyerek** seçiyor ve ayarı yeniden başlatmaya dayanıklı biçimde yazıyor.

**2. Bağlantıların yarısının rastgele kesilmesi.** Adres düzeldikten sonra bile bağlantıların yaklaşık yarısı anında resetleniyor. Başarısızlıklar kümelenmiyor, birbirinden bağımsız — yani yeniden denemek işe yarıyor.

Yeniden deneme yalnızca **istemciye tek bayt bile gitmeden önce** yapılıyor. Sunucudan yanıt gelip aktarıldıktan sonra yeniden denemek akışı bozardı.

## Denenip işe yaramayanlar

Bunları ölçtük ve bu hatta fark yaratmadıklarını gördük. Kod duruyor; başka davranış sergileyen ağlarda gerekebilir.

**TLS akışını parçalama.** Sabit konumdan bölme, alan adının ortasından bölme ve hiç bölmeme aynı başarısızlık oranını verdi (8 denemede 4).

**Düşük ömürlü sahte paket.** GoodbyeDPI'ın Windows'ta kullandığı teknik. TTL 1'den 8'e kadar tarandı; hiçbiri tabandan iyi değildi. Motor mekanik olarak doğru çalışıyor (paketleri yakalıyor, sahte kopyayı kuruyor ve gönderiyor) ama bu engeli aşmıyor.

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
├─ transparent/   yönlendirme + yeniden deneme (Linux) — nftables
├─ nfqueue/       sahte paket + TTL motoru (Linux) — NFQUEUE + ham soket
├─ dns/           çalışan adres kaynağı bulma ve yönlendirme
└─ cli/           tek komut: trdpi
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
- [x] Adres çözümleme düzeltmesi (kalıcı)
- [x] Yeniden deneme motoru
- [x] Tek komut arayüzü
- [ ] Açılışta otomatik başlatma
- [ ] QUIC erişilebilirlik ölçümü
- [ ] Grafik arayüz
- [ ] AppImage / deb / rpm paketleme
- [ ] Windows sistem geneli koruma

## Lisans

MIT. Bkz. [LICENSE](LICENSE).
