#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_URL="http://127.0.0.1:8501"

if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
  PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
elif [ -x "$SCRIPT_DIR/venv/bin/python" ]; then
  PYTHON_BIN="$SCRIPT_DIR/venv/bin/python"
else
  PYTHON_BIN="$(command -v python3)"
fi

open_browser() {
  sleep 6
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$APP_URL" >/dev/null 2>&1 || true
  fi
}

echo "[*] AEGIS launcher"
echo "[*] project: $SCRIPT_DIR"
echo "[*] python: $PYTHON_BIN"

if [ "$(id -u)" -ne 0 ]; then
  echo "[*] packet capture and auth.log reading require sudo"
  sudo -E "$PYTHON_BIN" "$SCRIPT_DIR/program/main.py" &
  MAIN_PID=$!
  open_browser &
  wait "$MAIN_PID"
  exit $?
fi

"$PYTHON_BIN" "$SCRIPT_DIR/program/main.py" &
MAIN_PID=$!
open_browser &
wait "$MAIN_PID"
