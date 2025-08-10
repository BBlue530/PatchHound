echo "[~] Installing dependencies..."

sudo apt-get update && sudo apt-get install -y jq curl

curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

if ! command -v trivy &> /dev/null; then
  echo "[~] Installing Trivy..."
  wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
  echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
  sudo apt-get update
  sudo apt-get install -y trivy
fi

if ! check_command pipx; then
  echo "[~] Installing pipx..."
  sudo apt-get install -y python3-pip
  python3 -m pip install --user pipx
  python3 -m pipx ensurepath
  export PATH="$PATH:$HOME/.local/bin"
fi

if ! check_command semgrep; then
  echo "[~] Installing semgrep..."
  pipx install semgrep
fi

if [ -n "$GHCR_PAT" ]; then
  echo "$GHCR_PAT" | docker login ghcr.io -u "$GITHUB_ACTOR" --password-stdin
else
  echo "[!] GHCR_PAT not set. Skipping Docker auth."
fi