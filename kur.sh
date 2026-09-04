#!/bin/sh
# TR-DPI kurulumu.
#
# Depoyu ekler ve paketi kurar. Sonraki güncellemeler sistemin kendi
# güncelleyicisinden gelir.
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Yönetici yetkisi gerekiyor. Şöyle çalıştır:"
    echo "  curl -fsSL https://furkan003.github.io/LinuxDpiTurkey/kur.sh | sudo sh"
    exit 1
fi

echo "TR-DPI kuruluyor..."

install -d -m 0755 /etc/apt/keyrings
curl -fsSL "https://furkan003.github.io/LinuxDpiTurkey/trdpi.gpg" -o /etc/apt/keyrings/trdpi.gpg
chmod 0644 /etc/apt/keyrings/trdpi.gpg

cat > /etc/apt/sources.list.d/trdpi.list <<KAYNAK
deb [signed-by=/etc/apt/keyrings/trdpi.gpg] https://furkan003.github.io/LinuxDpiTurkey stable main
KAYNAK

apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/trdpi.list \
    -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 >/dev/null
apt-get install -y trdpi

echo
echo "Kuruldu. Menüden TR-DPI'yi açıp BAŞLAT'a bas."
echo "Kaldırmak için: sudo apt remove trdpi"
