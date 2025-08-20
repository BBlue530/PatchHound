#!/bin/bash

set -e

VENV_DIR="./sbom_backend_venv"
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

echo "[i] Starting Gunicorn..."
"$VENV_DIR/bin/gunicorn" -w 2 --threads 4 -b 0.0.0.0:8080 --preload main:app