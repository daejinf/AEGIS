#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
  PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
elif [ -x "$SCRIPT_DIR/venv/bin/python" ]; then
  PYTHON_BIN="$SCRIPT_DIR/venv/bin/python"
else
  PYTHON_BIN="$(command -v python3)"
fi

echo "[*] AEGIS launcher"
echo "[*] project: $SCRIPT_DIR"
echo "[*] python: $PYTHON_BIN"

if [ "$(id -u)" -ne 0 ]; then
  echo "[*] packet capture and auth.log reading require sudo"
  exec sudo -E "$PYTHON_BIN" "$SCRIPT_DIR/program/main.py"
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/program/main.py"
