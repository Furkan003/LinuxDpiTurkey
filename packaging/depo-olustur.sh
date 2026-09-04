#!/usr/bin/env bash
# İmzalı apt deposu üretir.
#
# Kullanıcı depoyu bir kez ekler, sonrasında güncellemeler sistemin kendi
# güncelleyicisinden gelir — tıpkı diğer programlar gibi.
#
# Depo GitHub Pages'te barındırılır; indirmek için bu makinenin açık olması
# gerekmez. Bu makine yalnızca **yeni sürüm yayınlarken** lazım.
set -euo pipefail

KOK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SURUM="$(grep -m1 '^version' "$KOK/Cargo.toml" | cut -d'"' -f2)"
DEPO="${1:-$KOK/depo}"
KULLANICI="${GITHUB_KULLANICI:-Furkan003}"
PROJE="${GITHUB_PROJE:-LinuxDpiTurkey}"
ADRES="https://${KULLANICI,,}.github.io/${PROJE}"

# İmzalayacak anahtar. Birden fazla varsa ilki alınır.
ANAHTAR="$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/{print $5; exit}')"
if [ -z "$ANAHTAR" ]; then
  echo "İmza anahtarı bulunamadı." >&2
  exit 1
fi

PAKET="$KOK/dist/trdpi_${SURUM}_amd64.deb"
[ -f "$PAKET" ] || PAKET="$(ls "$KOK"/../trdpi-linux/trdpi_"${SURUM}"_amd64.deb 2>/dev/null | head -1)"
if [ ! -f "$PAKET" ]; then
  echo "Paket bulunamadı. Önce: bash packaging/deb-olustur.sh" >&2
  exit 1
fi

echo "TR-DPI $SURUM deposu hazırlanıyor..."
echo "  anahtar: $ANAHTAR"
echo "  adres  : $ADRES"

rm -rf "$DEPO"
mkdir -p "$DEPO/pool/main/t/trdpi" "$DEPO/dists/stable/main/binary-amd64"
cp "$PAKET" "$DEPO/pool/main/t/trdpi/"

# --- paket dizini -------------------------------------------------------
cd "$DEPO"
apt-ftparchive packages pool > dists/stable/main/binary-amd64/Packages
gzip -9kf dists/stable/main/binary-amd64/Packages

# --- Release ------------------------------------------------------------
# `Suite` ve `Codename` sabit: dağıtım sürümüne göre ayrı depo tutmuyoruz,
# çünkü paket zaten en eski desteklenen sürümde derleniyor ve hepsinde çalışıyor.
cat > dists/stable/Release <<EOF
Origin: TR-DPI
Label: TR-DPI
Suite: stable
Codename: stable
Version: $SURUM
Architectures: amd64
Components: main
Description: Turkiye'de engellenen sitelere erisimi acan uygulama
Date: $(date -Ru)
EOF
apt-ftparchive release dists/stable >> dists/stable/Release

# --- imzala -------------------------------------------------------------
# İki biçim de üretiliyor: eski apt sürümleri Release.gpg, yenileri InRelease
# kullanıyor.
gpg --default-key "$ANAHTAR" --batch --yes -abs \
    -o dists/stable/Release.gpg dists/stable/Release
gpg --default-key "$ANAHTAR" --batch --yes --clearsign \
    -o dists/stable/InRelease dists/stable/Release

# Açık anahtar: apt'ın beklediği ikili biçimde.
gpg --export "$ANAHTAR" > "$DEPO/trdpi.gpg"

# --- kurulum betiği -----------------------------------------------------
cat > "$DEPO/kur.sh" <<EOF
#!/bin/sh
# TR-DPI kurulumu.
#
# Depoyu ekler ve paketi kurar. Sonraki güncellemeler sistemin kendi
# güncelleyicisinden gelir.
set -e

if [ "\$(id -u)" -ne 0 ]; then
    echo "Yönetici yetkisi gerekiyor. Şöyle çalıştır:"
    echo "  curl -fsSL $ADRES/kur.sh | sudo sh"
    exit 1
fi

echo "TR-DPI kuruluyor..."

install -d -m 0755 /etc/apt/keyrings
curl -fsSL "$ADRES/trdpi.gpg" -o /etc/apt/keyrings/trdpi.gpg
chmod 0644 /etc/apt/keyrings/trdpi.gpg

cat > /etc/apt/sources.list.d/trdpi.list <<KAYNAK
deb [signed-by=/etc/apt/keyrings/trdpi.gpg] $ADRES stable main
KAYNAK

apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/trdpi.list \\
    -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 >/dev/null
apt-get install -y trdpi

echo
echo "Kuruldu. Menüden TR-DPI'yi açıp BAŞLAT'a bas."
echo "Kaldırmak için: sudo apt remove trdpi"
EOF
chmod +x "$DEPO/kur.sh"

# --- karşılama sayfası --------------------------------------------------
cat > "$DEPO/index.html" <<EOF
<!doctype html>
<meta charset="utf-8">
<title>TR-DPI</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root { color-scheme: dark }
  body { background:#14161a; color:#e6e8eb; font:16px/1.6 system-ui,sans-serif;
         max-width:44rem; margin:0 auto; padding:3rem 1.5rem }
  h1 { font-size:2rem; margin:0 0 .3rem }
  p.alt { color:#9aa0a8; margin-top:0 }
  pre { background:#1e2128; border:1px solid #2c3038; border-radius:6px;
        padding:1rem; overflow-x:auto; font-size:14px }
  a { color:#4fc2a0 }
  .not { color:#9aa0a8; font-size:14px }
</style>
<h1>TR-DPI</h1>
<p class="alt">Türkiye'de engellenen sitelere erişimi açan Linux uygulaması.</p>

<h2>Kurulum</h2>
<pre>curl -fsSL $ADRES/kur.sh | sudo sh</pre>
<p class="not">Depoyu ekler ve kurar. Güncellemeler bundan sonra sistemin kendi
güncelleyicisinden gelir.</p>

<h2>Kullanım</h2>
<p>Menüden <b>TR-DPI</b>'yi aç, <b>BAŞLAT</b>'a bas.</p>

<h2>Kaldırma</h2>
<pre>sudo apt remove trdpi</pre>

<p><a href="https://github.com/$KULLANICI/$PROJE">Kaynak kodu ve ayrıntılar</a></p>
EOF

echo
echo "Hazır: $DEPO"
du -sh "$DEPO" | awk '{print "  boyut: " $1}'
echo "  paket: $(ls pool/main/t/trdpi/)"
