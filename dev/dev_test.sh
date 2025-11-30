#!/bin/bash
set -e

BASE_DIR="$HOME/Desktop/PatchHound"
BACKEND_LOG="$BASE_DIR/backend.log"
SECRETS_DIR="$BASE_DIR/src/Backend/secrets.json"
mkdir -p "$(dirname "$BACKEND_LOG")"

if ! command -v xfce4-terminal &>/dev/null; then
    echo "[~] xfce4-terminal not found, installing..."
    sudo apt update
    sudo apt install -y xfce4-terminal
fi

echo "[~] Starting backend..."
tmux new-session -d -s patchhound "cd '$BASE_DIR/src/Backend' && bash Start.sh"
tmux pipe-pane -t patchhound 'cat >> '"$BACKEND_LOG"

nohup xfce4-terminal --hold --command="bash -c 'tmux attach-session -t patchhound; exec bash'" >/dev/null 2>&1 &

echo "[~] Waiting for API key..."
while ! grep -q '"api_key"' "$SECRETS_DIR"; do
    sleep 3
done

API_KEY=$(grep '"api_key"' "$SECRETS_DIR" | sed -E 's/.*"api_key": *"(.*)".*/\1/')
echo "[+] API KEY FOUND: $API_KEY"

echo "[+] Installing CLI..."
bash "$BASE_DIR/src/PatchHound_CLI/install.sh"

echo "[~] Configuring CLI..."
patchhound config --set BASE_URL http://localhost:8080 \
    REPO_NAME test-repo \
    AUTHOR_NAME "dev_test" \
    AUTHOR_EMAIL "dev_test@example.com" \
    TRIVY_SCAN true \
    SAST_SCAN true \
    TARGET "$BASE_DIR/src"

echo "[~] Waiting for backend to start..."
while ! curl -s http://localhost:8080/v1/health-check >/dev/null; do
    echo "[~] Backend not ready, retrying..."
    sleep 10
done
sleep 30

echo "[~] Creating new token..."
patchhound create --api-key "$API_KEY" --org test_org --exp 30 | tee "$BACKEND_LOG"

TOKEN_KEY=$(grep -A1 "Token Key Created" "$BACKEND_LOG" | tail -n1 | awk '{print $1}' | tr -d '\r')
echo "[+] Token: $TOKEN_KEY"

sudo patchhound scan --token "$TOKEN_KEY"