# TR-DPI

Türkiye'de engellenen sitelere erişimi açan Linux uygulaması. Aç, düğmeye bas, biter.

<p align="center">
  <img src="packaging/ekran.png" alt="TR-DPI penceresi" width="380">
</p>

VPN değil. Uzak sunucu yok, hesap yok, üyelik yok. Trafiğin başka bir yere yönlendirilmiyor.

---

## Kurulum

```bash
curl -fsSL https://furkan003.github.io/LinuxDpiTurkey/kur.sh | sudo sh
```

Depoyu ekler ve kurar. **Güncellemeler bundan sonra sistemin kendi güncelleyicisinden gelir** — Ubuntu "güncelleme var" dediğinde bu da listede olur.

Terminal istemiyorsan: [Releases](https://github.com/Furkan003/LinuxDpiTurkey/releases) sayfasından `.deb` dosyasını indir, **çift tıkla.**

**Arch / Manjaro / EndeavourOS:**

```bash
git clone https://github.com/Furkan003/LinuxDpiTurkey.git
cd LinuxDpiTurkey/packaging/aur
makepkg -si
```

*(AUR kaydı Arch tarafında geçici olarak kapalı. Açıldığında `yay -S trdpi-bin` de çalışacak.)*

Kaldırmak için: `sudo apt remove trdpi` (Arch'ta `yay -R trdpi-bin`)

## Kullanım

Menüden **TR-DPI**'yi aç, **BAŞLAT**'a bas. Yönetici parolan bir kez sorulur.

Pencereyi kapatabilirsin; koruma çalışmaya devam eder. Durdurmak için tekrar açıp **DURDUR**'a bas.

Terminal kullanmak isteyenler için:

| Komut | Ne yapar |
|---|---|
| `sudo trdpi` | ölç, düzelt, koru |
| `trdpi --olc` | yalnızca ölç, hiçbir şey değiştirme (yetki istemez) |
| `sudo trdpi --sure 600` | 10 dakika sonra kendiliğinden geri al |
| `sudo trdpi --durdur` | çalışan kopyaları durdur |
| `sudo trdpi --geri` | yapılan her değişikliği geri al |
| `sudo trdpi --quic-gecir` | QUIC'e hiç dokunma (aşağıya bak) |

## Gerçekten işe yarıyor mu

Gerçek bir Türkiye hattında ölçüldü (Ubuntu 24.04, her hedefe 15 deneme). Koruma kapatılıp tekrar açılarak kontrol edildi:

| | discord.com | roblox.com |
|---|---|---|
| Koruma yok | 0/15 | 0/15 |
| Yalnızca adres düzeltmesi | 8/15 | 7/15 |
| **Tam koruma** | **14/15** | **15/15** |
| Yalnızca adres düzeltmesi *(kontrol)* | 7/15 | 8/15 |

## Hızı düşürüyor mu

Hayır. Koruma açıkken ve kapalıyken aynı hattan ölçüldü:

| | Koruma kapalı | Koruma açık |
|---|---|---|
| 10 MB indirme | 8.20 MB/s | 8.20 MB/s |
| Sayfa açılışı (TCP 443) | 0.171 s | 0.172 s |
| Gerçek zamanlı yol (STUN) | 153 ms | 147 ms |
| Durdurma | — | **0.10 s** |

Trafik yerel bir motordan geçiyor ama motor veriyi kopyalamıyor; çekirdek iki bağlantıyı doğrudan birbirine bağlıyor.

## Nasıl çalışıyor

Ölçtüğümüz hatta engel **iki katmanlıydı**; uygulama ikisini de çözüyor.

**1. Adres çözümlemesine müdahale.** Engellenen siteler sorulduğunda sistem sahte bir adres alıyor (`195.175.254.2` — OONI ölçümlerinde Türkiye'de sansür yanıtı olarak belgelenen adres). O adrese hiçbir şekilde ulaşılamıyor.

Basit görünen çözüm işe yaramıyor: "adres sunucusunu 1.1.1.1 yap" dediğinde de bağlanamıyorsun, çünkü dışarıdaki adres sunucularının standart kapısı kapalı. Uygulama bu yüzden **standart dışı kapıdan** soran kaynakları deneyip çalışanı buluyor.

Adres soruları **şifreli** gidiyor (DNS-over-TLS). Bu, standart dışı kapıdan düz sorgu göndermekten daha sağlam: sorgunun içi görünmediği için alan adına göre süzülemiyor. Şifreli yol tutmazsa standart dışı kapıya, o da tutmazsa yönlendirme kuralına düşülüyor.

Uygulama şifreli yolu **kurup doğruluyor** — kapının açık olması çalıştığı anlamına gelmiyor. Engellendiği bilinen bir adı çözüp yanıtın sansür adresi olup olmadığına bakıyor; değilse kabul ediyor, öyleyse geri alıp bir sonrakini deniyor.

Ölçüldü: şifresiz `discord.com` → `195.175.254.2` (sansür adresi), şifreliyken → `162.159.128.233` ve diğer gerçek adresler.

Ayar **bağlantı bazında** uygulanıyor ve açılışta aynı komutu tekrarlayan küçük bir systemd birimiyle kalıcılaşıyor. Genel (global) ayar dosyası yazmak işe yaramıyordu: systemd-resolved sorguları bağlantının kendi çözümleyicisine yönlendirdiği için, DHCP'den adres alan her kurulumda genel ayar hiç devreye girmiyordu. Ölçüldü ve düzeltildi.

**2. QUIC engeli.** Tarayıcılar ve Electron uygulamaları (Discord bunlardan biri) önce QUIC deniyor — UDP 443 üzerinden çalışan yeni ve daha hızlı bağlantı yöntemi.

Bu yolun nasıl engellendiğini ölçtük: **DPI, QUIC Initial paketini çözüp içindeki sunucu adını okuyor** ve engelli ada denk gelince datagramı düşürüyor. Kanıt kesin — aynı IP'ye, aynı porttan, tek değişken sunucu adı:

| İstek | Sonuç |
|---|---|
| Discord'un IP'si + `cloudflare-quic.com` adı | el sıkışma **0.75 sn** |
| Discord'un IP'si + `discord.com` adı | **zaman aşımı** |

**Uygulama bu engeli aşıyor.** Gerçek paketten hemen önce, hedefe ulaşamayacak kadar düşük ömürlü ikinci bir Initial gönderiliyor. Denetim kararını o pakete göre veriyor; sahte paket yolda ölüyor, gerçek paket geçiyor.

Sahte paket **geçerli** bir Initial: gerçekten çözülebiliyor ve içinde masum bir sunucu adı var. Bu önemli, çünkü gövdesi rastgele olan bir sahteyi denetim "çözemedim, karar vermem" diye yok sayabilir — o zaman teknik ölür. Geçerli paketi çözüyor, meşru bir ad görüyor ve geçiriyor.

Bunun için gereken kripto (SHA-256, HMAC, HKDF, AES-128-GCM) kütüphane eklemeden yazıldı: motor root çalışıyor ve her dolaylı paket root yetkisiyle çalışan koda giriyor. Üretilen anahtarlar RFC 9001'in resmî test vektörleriyle birebir doğrulanıyor.

Ölçüldü — Discord'a HTTP/3 isteği:

| | Sonuç |
|---|---|
| Koruma kapalı | yanıt yok |
| Koruma açık | **HTTP/3 200**, 0.15-0.19 sn |

Aynı sayfa korunan TCP yolundan 0.88 saniye sürüyor. Yani engeli aşmak, kapatmaya göre **beş kat hızlı.**

Sahte paketin ömrü ayarlanabilir; varsayılan iki değer (4 ve 8) gönderiliyor, çünkü denetimin kaç sıçrama uzakta olduğu ağdan ağa değişir. Bu hatta ölçüm: TTL 1-2 çalışmıyor, **3-12 arası 18 denemenin 18'i başarılı.**

Denenip elenenler, ölçümle:

| Yöntem | Sonuç |
|---|---|
| IP parçalama | işe yaramadı — denetim parçaları birleştiriyor |
| bozuk sağlama toplamı tek başına | işe yaramadı — denetim toplamı doğruluyor |
| aynı pakete ömür + bozuk toplam | **çalışanı da bozuyor** |
| geçerli Initial + düşük ömür | **6/6 başarılı** |

Bozuk toplam listede kalıyor: toplamı doğrulamayan denetimlerde işe yarayabilir ve ayrı bir paket olarak gönderildiği için burada zarar vermediği ölçüldü.

Motor QUIC'i aşamazsa (çekirdek desteği ya da yetki yoksa) eski davranışa düşülür: UDP 443 reddedilir ve uygulamalar anında korunan TCP yoluna geçer. **Oyunların ve sesli görüşmenin gerçek zamanlı trafiğine hiçbir durumda dokunulmuyor** — o trafik yüksek portlarda akar. İstemeyen `--quic-gecir` ile QUIC'i tamamen serbest bırakabilir.

**3. Adresin tümüyle kapatılması.** Bazen engel alan adına değil, belirli bir adrese konuyor: o adrese giden hiçbir paket dönmüyor. Aynı alan adı çoğu zaman birden fazla adreste durduğu için (büyük siteler onlarca adres kullanır), engel hepsine konmamış olabilir.

Özgün adres hiçbir denemede yanıt vermezse uygulama, istemcinin gönderdiği site adını okuyup **adresi kendisi yeniden çözümlüyor** ve kalan adresleri sırayla deniyor. IPv4 kapalıyken IPv6 açık olabildiği için aile kısıtlaması da yok.

Ölçüldü — bir adres karadeliğe atıldı, aynı istek iki kez yapıldı:

| | Sonuç |
|---|---|
| Koruma kapalı | açılmıyor (40 s zaman aşımı) |
| Koruma açık | **8.5 s'de açılıyor**, başka adresten |

Yeniden çözümlemede yalnızca dış adresler kabul ediliyor: zehirlenmiş bir yanıt yerel ağdaki bir makineyi gösterirse ona bağlanılmaz.

**4. Bağlantıların rastgele kesilmesi.** Adres düzeldikten sonra bile bağlantıların yaklaşık yarısı anında kesiliyor. Kesilmeler kümelenmiyor, birbirinden bağımsız — bu yüzden **yeniden denemek** işe yarıyor.

Yeniden deneme yalnızca tarayıcına ya da uygulamana tek bayt bile ulaşmadan önce yapılıyor. Yanıt gelmeye başladıktan sonra yeniden denemek veriyi bozardı.

## Denenip işe yaramayanlar

Bunları yazdık, ölçtük ve bu hatta fark yaratmadıklarını gördük. Kod duruyor; başka davranan ağlarda gerekebilir.

**Trafiği parçalama.** Sabit konumdan bölme, site adının ortasından bölme, hiç bölmeme — üçü de aynı başarısızlık oranını verdi.

**Düşük ömürlü sahte paket.** GoodbyeDPI'ın Windows'ta kullandığı teknik. Ömür değeri 1'den 8'e tarandı, hiçbiri tabandan iyi çıkmadı. Motor mekanik olarak doğru çalışıyor — paketi yakalıyor, sahte kopyayı kuruyor, gönderiyor — ama bu engeli aşmıyor.

## Kaynak kullanımı

Sürekli çalışan tek şey motor. Pencere yalnızca sen açtığında duruyor.

| | Bellek | Dosya |
|---|---|---|
| Motor *(sürekli çalışan)* | **0.65 MB** | 0.9 MB |
| Pencere *(açıkken)* | **16 MB** | 1.2 MB |
| *NetworkManager (karşılaştırma)* | *18 MB* | |
| *Thunar (karşılaştırma)* | *42 MB* | |

Arayüzde web motoru ve OpenGL kullanılmıyor. Aynı pencereyi OpenGL ile de yazıp ölçtük: 115 MB. Ölçüm kararı verdi.

## Hangi dağıtımlarda çalışır

Ubuntu 22.04+ · Debian 12+ · Linux Mint · Pop!_OS · Zorin · elementary · Fedora 36+ · Arch / Manjaro

Paket, desteklenmek istenen **en eski** dağıtımda derleniyor: eski kütüphaneyle derlenen yenide çalışır, tersi çalışmaz. Motor tamamen durağan derlendiği için hiçbir sistem kütüphanesine bağlı değil.

## Gerçek zamanlı bağlantı (oyun, sesli görüşme)

Oyunların ve sesli görüşmenin trafiği yüksek portlarda UDP ile akar. Uygulama bu yola **dokunmuyor** — dolayısıyla ne bozuyor ne de açıyor.

Bunu iddia etmek yerine ölçüyoruz: her teşhis turunda gerçek zamanlı yolun açık olup olmadığı, oyunların bağlanırken kullandığı protokolün (STUN) kendisiyle sınanıyor ve sonuç ekranda yazıyor:

```
QUIC (UDP 443): kapalı · Gerçek zamanlı yol (oyun, sesli görüşme): açık
```

Koruma açıkken ölçüldü: gerçek zamanlı yol 147 ms'de yanıt veriyor, kapalıyken 153 ms. Fark yok.

## Ne yapmaz

**Gerçek zamanlı trafikteki engeli açmaz.** Yukarıdaki ölçüm "kapalı" diyorsa engel UDP tarafında demektir; bunu aşmak paket düzeyinde ayrı bir iş ve henüz yapılmıyor. Ölçtüğümüz hiçbir hatta bu yol kapalı çıkmadı — kapalı bir hat görmeden yazılacak çözüm, doğruluğu sınanamayan bir çözüm olurdu.

**Adresin her yolunun kapatılmasını aşamaz.** Alan adının bütün adresleri engellenmişse yapılabilecek bir şey kalmıyor; trafiği başka bir ülkeden geçirmek gerekir ve bu VPN demektir.

**Seni gizlemez.** Bu bir VPN değil; kim olduğunu saklamıyor, yalnızca engellenen adreslere ulaşmanı sağlıyor.

## Farklı operatörler, farklı yöntemler

Engelleme yöntemi operatörden operatöre değişiyor: kimi adrese bakıyor, kimi alan adına. Bu yüzden uygulama tek bir tekniğe bağlı kalmıyor.

Bağlantılar kurulmuyorsa kendiliğinden bir sonraki tekniğe geçiyor — en az altı bağlantıya bakıp, kurulamayan oranı %30'u aşarsa. Sağlıklı bir hatta hiç devreye girmiyor.

| Basamak | Teknik |
|---|---|
| 1 | yeniden deneme (varsayılan) |
| 2 | site adını iki parçaya bölme |
| 3 | sabit konumdan bölme |
| 4 | sahte paket gönderme |

Hepsi tükenirse bunu açıkça söylüyor: *"Denenecek teknik kalmadı ve bağlantılar hâlâ kurulamıyor."*

## Adres düzeltmesi çalışmazsa

`systemd-resolved` olmayan dağıtımlarda çözümleyiciyi sistemin aracıyla değiştiremiyoruz. O durumda giden adres sorularını **doğrudan çalışan sunucuya çeviriyoruz.** Bu her dağıtımda çalışıyor ve kendi adres sunucusunu kullanan uygulamaları bile düzeltiyor.

Ölçüldü: kural varken `dig @1.1.1.1 discord.com` doğru adresleri döndürüyor, kural yokken boş dönüyor.

## Root olarak çalışan uygulamalar

Döngüyü önlemek için kendi trafiğimizi kural dışı bırakmamız gerekiyor. Bu, "motorun kullanıcı kimliğini muaf tut" diye yapılırsa motor root çalıştığı için **root olarak çalışan her uygulama** kapsam dışı kalıyordu — `apt`, sistem servisleri, `sudo` ile çalıştırılan her şey.

Artık yalnızca **bizim açtığımız soketler** muaf: giden bağlantıya bir işaret konuyor ve kural o işareti muaf tutuyor. Ölçüldü: root olarak yapılan üç istek sayacı 0'dan 3'e çıkardı, yani artık motordan geçiyorlar.

## Açılışta başlatma — isteğe bağlı

Paket bir systemd servisi kuruyor ama **etkinleştirmiyor.** Koruma sistem geneli değişiklik yapıyor ve bunun senin kararın olması gerekiyor.

```bash
trdpi --acilista              # durum
sudo trdpi --acilista-ac      # açılışta başlasın
sudo trdpi --acilista-kapat   # başlamasın
```

Arayüzde de bir anahtar var. Servis çökerse üç denemede vazgeçiyor: koruma kapalı kalması internetin kesilmesinden iyidir.

## Bir site açılmıyorsa

**Arayüzden:** site adını yaz, *Dene* düğmesine bas. Komut bilmen gerekmiyor.

Terminalden aynısı:

```bash
trdpi --dene discord.com
```

O siteye özel cevap veriyor — yönetici yetkisi istemeden:

```
  Adres çözümleme   yanlış adres veriliyor
  Bağlantı          yanıt gelmiyor
  Güvenli aşama     ölçülemedi
  QUIC              site adına göre engelli
```

Adres çözümleme bozuksa gerçek adresi çalışan bir kaynaktan alıp QUIC'i ona göre ölçüyor; yoksa sinkhole'a ölçüm yapmış olurduk.

## Hattını raporlamak

Arayüzde *Hat raporunu kaydet* düğmesi bunu ev dizinine yazıyor. Terminalden:

```bash
trdpi --rapor
```

Bu hattın neyi nasıl engellediğini çıkarıyor: hangi adres kaynakları çalışıyor, hangi kapılar açık, hangi siteler nasıl engelli. **Telemetri yok** — çıktı ekranda kalıyor, paylaşmak sana kalmış.

Başka bir operatörde çalıştırıp karşılaştırmak için var. Ölçemediğimiz tek şey ikinci bir hattı görmekti.

## Bellek

Ölçüldü: **boşta 0.8 MB, 40 eş zamanlı bağlantıda 2.2 MB.** Bağlantı biter bitmez geri iniyor.

İş parçacığı yığınları 2 MiB'den 128 KiB'e indirildi; bu yol sığ çalışıyor ve tamponlar öbekte. Sanal bellek 174 MB'den 7 MB'ye düştü. ClientHello tamponu da okunan boyuta küçültülüyor — bağlantı boyunca 16 KB boşuna durmuyor.

## Motor çökerse

Yönlendirme kuralı dururken dinleyen bir motor yoksa **bütün HTTPS kesilir** — ölçüldü, istek 13 ms'de reddediliyor. Bu yüzden motor açılırken yanında küçük bir gözcü süreç başlatıyor. Motor nasıl ölürse ölsün (`kill -9`, bellek yetersizliği, panik) gözcü kuralları kaldırıyor ve adres ayarını geri getiriyor.

Ölçüldü: motor `kill -9` ile öldürüldükten sonra nftables tabloları **0**, kimlik dosyası silinmiş, internet çalışıyor (`kod=200`). Gözcü olmasaydı bu `000` olurdu.

QUIC tarafında bu sorun yok: kuyruk kuralı `bypass` bayrağıyla kuruluyor, motor ölse de paketler geçer.

## IPv6

Yönlendirme IPv6'yı da kapsıyor — ama **yalnızca taşıyabildiğimizi sınayıp doğruladıktan sonra.**

Sorun şu: `redirect` kuralı IPv6'yı yakalayabilir ama biz bağlantının özgün hedefini okuyamazsak onu iletemeyiz ve trafik tamamen kesilir. O yüzden motor her açılışta geçici bir kural kurup kendi kendine bir bağlantı yapıyor ve çekirdeğin NAT öncesi hedefi doğru verdiğini görüyor. Sınama geçerse IPv6 kuralları kuruluyor, geçmezse IPv6'ya hiç dokunulmuyor: korumasız ama **çalışır** kalıyor.

Sınama loopback üzerinde yapılıyor; ölçülen şey adresin küresel olup olmamasına bakmadığı için IPv6 bağlantısı olmayan makinede bile mekanizma doğrulanabiliyor.

## Gizlilik

Telemetri yok. Ölçüm sonuçları hiçbir sunucuya gönderilmiyor.

Program açılınca yeni sürüm var mı diye bakar ve varsa söyler — **kendiliğinden kurmaz.** Motor yönetici yetkisiyle çalıştığı için, sessizce indirilen bir dosyayı root olarak çalıştırmak kabul edilemez bir risk olurdu.

Şunun farkında ol: **ölçümün kendisi ağ üzerinde gözlemlenebilir.** Uygulama bilinen hedeflere istek atar; bu, bağlantını sağlayan taraf için görünür bir izdir. Bu yüzden hedef listesi kısa tutuluyor ve ölçüm arka planda sürekli çalıştırılmıyor.

## Güvenlik tasarımı

- **Pencere asla root çalışmaz.** Yetki gereken işler polkit ile yapılır; masaüstü kendi parola penceresini gösterir.
- **Yalnızca kendi kurallarımıza dokunuruz.** Oluşturulan her firewall kuralı oturum kimliğiyle etiketlenir. Docker, güvenlik duvarı gibi yabancı kurallar ne yedeklenir ne silinir — ve hiçbir komut toplu silme yapmaz.
- **Motor çökerse internet kesilmez.** Kural, dinleyen program yoksa paketleri geçiren biçimde kurulur.
- **Her değişiklik geri alınabilir.** Paket kaldırılırken ağ ayarları da eski haline döner.
- **Ölçüm yokluğu "sorun yok" sayılmaz.** Veri toplanamadıysa sonuç *bilinmiyor*'dur.

## Geliştirme

Rust 1.82+ gerekir.

```bash
cargo test                                   # 345 test
cargo clippy --all-targets -- -D warnings
cargo build -p trdpi-gui                     # arayüz (yalnızca Linux)
bash packaging/deb-olustur.sh                # .deb üret
```

```
crates/
├─ core/          kanonik tipler — I/O yok, platform kodu yok
├─ diagnostics/   ağ ölçümü ve öneri — yetki gerektirmez
├─ dns/           çalışan adres kaynağı bulma ve yönlendirme
├─ transparent/   yönlendirme + yeniden deneme (Linux)
├─ nfqueue/       sahte paket motoru (Linux)
├─ proxy/         yerel SOCKS5 motoru
├─ cli/           tek komut: trdpi
└─ gui/           pencere — web motoru yok
```

Testlerin tamamı gerçek ağ olmadan çalışır. Dağıtım uyumluluğu için `.deb` Ubuntu 22.04 ortamında üretilmelidir.

## Yol haritası

- [x] Ağ ölçümü ve teşhis
- [x] Adres çözümleme düzeltmesi (kalıcı)
- [x] Yeniden deneme motoru
- [x] Grafik arayüz
- [x] Çift tıkla kurulum (.deb)
- [x] Yeni sürüm bildirimi
- [x] İmzalı apt deposu
- [x] AUR paketi (Arch)
- [x] QUIC (UDP 443) kapsamı
- [x] QUIC engelini aşma (sahte Initial + düşük TTL)
- [x] Motor çökerse kuralları kaldıran gözcü
- [x] IPv6 (açılışta sınanarak)
- [x] Düz HTTP (port 80) kapsamı
- [x] Root olarak çalışan uygulamalar da kapsamda
- [x] Teknik yükseltme merdiveni
- [x] systemd-resolved olmayan dağıtımlar için adres çevirme
- [x] Şifreli adres çözümleme (DNS-over-TLS)
- [x] Geçerli sahte QUIC Initial (kütüphanesiz kripto)
- [x] İsteğe bağlı açılışta başlatma
- [x] Tek site teşhisi (`--dene`) ve hat raporu (`--rapor`)
- [x] Arayüzde canlı durum
- [x] Çalışan tekniği hatırlama
- [x] Gerçek zamanlı yol ölçümü
- [ ] Açılışta otomatik başlatma
- [ ] AppImage ve .rpm
- [x] Adres engelinde başka adrese geçme
- [ ] Gerçek zamanlı trafikte engel aşma *(ölçümde kapalı bir hat görülünce)*

## Lisans

MIT. Bkz. [LICENSE](LICENSE).
