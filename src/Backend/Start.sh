#!/bin/bash

set -e

VENV_DIR="./venv"
REQUIREMENTS_FILE="requirements.txt"

if ! command -v python3 &>/dev/null; then
  echo "[!] python3 is not installed or not in PATH."
  exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
  echo "[i] Creating virtual environment..."
  python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
pip install --upgrade pip

if [ -f "$REQUIREMENTS_FILE" ]; then
  echo "[i] Installing dependencies from $REQUIREMENTS_FILE..."
  pip install -r "$REQUIREMENTS_FILE"
else
  echo "[!] $REQUIREMENTS_FILE not found."
fi

echo "[+] Starting..."
python3 app.py