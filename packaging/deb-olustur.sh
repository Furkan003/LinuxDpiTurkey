#!/usr/bin/env bash
# .deb paketi üretir.
#
# Çift tıklanınca kurulan, menüde ikonu çıkan bir paket hedefliyoruz.
# Kullanıcı hiçbir komut yazmayacak.
#
# Derleme, desteklenmek istenen **en eski** dağıtımda yapılmalıdır:
# eski kütüphaneyle derlenen yenide çalışır, tersi çalışmaz.
set -euo pipefail

KOK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SURUM="$(grep -m1 '^version' "$KOK/Cargo.toml" | cut -d'"' -f2)"
MIMARI="amd64"
CIKTI="${1:-$KOK/dist}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "TR-DPI $SURUM paketleniyor..."

# --- derle -------------------------------------------------------------
# Motor: hiçbir sistem kütüphanesine bağlı olmasın diye durağan.
echo "  motor derleniyor (durağan)..."
cargo build --release --target x86_64-unknown-linux-musl \
  -p trdpi-cli --bin trdpi >/dev/null

# Arayüz: grafik sürücüsüne erişmesi gerektiği için sistem kütüphanelerini
# kullanır; bağımlılıkları paket içinde bildiriliyor.
echo "  arayüz derleniyor..."
cargo build --release -p trdpi-gui >/dev/null

MOTOR="$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
  | grep -o '"target_directory":"[^"]*"' | cut -d'"' -f4)"
MOTOR="${MOTOR:-$KOK/target}"

# --- yerleştir ---------------------------------------------------------
install -Dm755 "$MOTOR/x86_64-unknown-linux-musl/release/trdpi" \
  "$STAGE/usr/bin/trdpi"
install -Dm755 "$MOTOR/release/trdpi-arayuz" \
  "$STAGE/usr/bin/trdpi-arayuz"
install -Dm644 "$KOK/packaging/trdpi.desktop" \
  "$STAGE/usr/share/applications/trdpi.desktop"
install -Dm644 "$KOK/packaging/trdpi.svg" \
  "$STAGE/usr/share/icons/hicolor/scalable/apps/trdpi.svg"
install -Dm644 "$KOK/packaging/tr.trdpi.policy" \
  "$STAGE/usr/share/polkit-1/actions/tr.trdpi.policy"
install -Dm644 "$KOK/packaging/trdpi.service" \
  "$STAGE/usr/lib/systemd/system/trdpi.service"
install -Dm644 "$KOK/LICENSE" \
  "$STAGE/usr/share/doc/trdpi/copyright"

BOYUT="$(du -sk "$STAGE" | cut -f1)"

# --- paket bilgisi -----------------------------------------------------
# Bağımlılıklar masaüstü kuran her sistemde zaten var; yine de bildiriyoruz
# ki eksikse paket yöneticisi kendisi çözsün.
mkdir -p "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: trdpi
Version: $SURUM
Section: net
Priority: optional
Architecture: $MIMARI
Depends: libc6 (>= 2.35), libx11-6, libxkbcommon0, libgl1, libwayland-client0, nftables, policykit-1 | polkit
Recommends: systemd-resolved
Installed-Size: $BOYUT
Maintainer: TR-DPI
Description: Engellenen sitelere erisimi acar
 Bağlantındaki engeli önce ölçer, sonra ona uygun yöntemi kendisi seçer.
 Terminal gerekmez: pencereyi aç, düğmeye bas.
 .
 Adres çözümlemesine yapılan müdahaleyi düzeltir ve rastgele kesilen
 bağlantıları yeniden dener. Yaptığı her değişiklik geri alınabilir.
EOF

# Kaldırılırken sistemde iz bırakmasın.
cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
# Koruma çalışıyorsa durdur ve ağ ayarlarını eski haline getir.
# Açılışta başlatma açıksa kapat, sonra ağ ayarlarını geri al.
if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now trdpi.service >/dev/null 2>&1 || true
fi
if [ -x /usr/bin/trdpi ]; then
    /usr/bin/trdpi --geri >/dev/null 2>&1 || true
fi
EOF
chmod 755 "$STAGE/DEBIAN/prerm"

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -qtf /usr/share/icons/hicolor || true
fi
EOF
chmod 755 "$STAGE/DEBIAN/postinst"

# --- paketle -----------------------------------------------------------
mkdir -p "$CIKTI"
PAKET="$CIKTI/trdpi_${SURUM}_${MIMARI}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$PAKET" >/dev/null

echo
echo "Hazır: $PAKET"
ls -lh "$PAKET" | awk '{print "  boyut: " $5}'
echo
echo "Kurulum: dosyaya çift tıkla, ya da"
echo "  sudo apt install $PAKET"
