#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$HOME/.local/share/applications"
DESKTOP_DIR="$HOME/Desktop"
APP_FILE="$APP_DIR/AEGIS.desktop"
DESKTOP_FILE="$DESKTOP_DIR/AEGIS.desktop"

mkdir -p "$APP_DIR"
mkdir -p "$DESKTOP_DIR"

cat > "$APP_FILE" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=AEGIS
Comment=Run the AEGIS monitoring stack
Exec=gnome-terminal -- bash -lc 'cd "$SCRIPT_DIR" && ./run_aegis.sh; exec bash'
Icon=utilities-terminal
Terminal=false
Categories=Development;Security;
StartupNotify=true
EOF

cp "$APP_FILE" "$DESKTOP_FILE"
chmod +x "$APP_FILE" "$DESKTOP_FILE" "$SCRIPT_DIR/run_aegis.sh"

if command -v gio >/dev/null 2>&1; then
  gio set "$DESKTOP_FILE" metadata::trusted true >/dev/null 2>&1 || true
fi

echo "[*] launcher installed"
echo "[*] desktop file: $DESKTOP_FILE"
echo "[*] app file: $APP_FILE"
echo "[*] double-click AEGIS on your desktop to launch"
