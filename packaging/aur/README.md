# AUR paketi

Arch ve türevleri (Manjaro, EndeavourOS, CachyOS) için.

AUR'a gönderildikten sonra:

```bash
yay -S trdpi-bin
```

Şimdilik doğrudan bu klasörden kurulabilir:

```bash
git clone https://github.com/Furkan003/LinuxDpiTurkey.git
cd LinuxDpiTurkey/packaging/aur
makepkg -si
```

## Bu klasör ne işe yarar

`PKGBUILD` ve `.SRCINFO`, AUR'a gönderilen iki dosya. AUR paketin kendisini
barındırmaz; yalnızca "nasıl derlenir" tarifini tutar. Kullanıcının makinesi
kaynağı GitHub'dan çekip kendi derler.

## Neden kaynaktan derlemiyor

Önce kaynaktan derleyen bir PKGBUILD yazdık ve Arch'ta test ettik: **çalışmadı.**
Arch'ın CMake 4 sürümü arayüz kütüphanesini eksik derliyor, `Fl_Button_deactivate`
gibi semboller üretilmiyor ve bağlama başarısız oluyor. Aynı kod CMake 3 ile
sorunsuz derleniyor, ama kullanıcının CMake sürümünü seçemeyiz.

Hazır paket zaten en eski desteklenen dağıtımda (glibc 2.34) üretiliyor ve
Arch'ta çalışıyor. Yan fayda: kullanıcı derleme beklemiyor.

## Yeni sürüm yayınlarken

1. `pkgver` değerini `Cargo.toml` ile aynı yap
2. `.SRCINFO` dosyasını yeniden üret:

```bash
makepkg --printsrcinfo > .SRCINFO
```

3. AUR deposuna gönder:

```bash
git -C aur-trdpi add PKGBUILD .SRCINFO
git -C aur-trdpi commit -m "0.1.1"
git -C aur-trdpi push
```

## İlk kurulum (bir kereye mahsus)

AUR'a gönderebilmek için hesap ve SSH anahtarı gerekiyor:

1. https://aur.archlinux.org/register hesap aç
2. Hesap ayarlarına açık SSH anahtarını ekle
3. Boş depoyu klonla:

```bash
git clone ssh://aur@aur.archlinux.org/trdpi-bin.git aur-trdpi
```

4. Bu klasördeki iki dosyayı kopyala, gönder.
