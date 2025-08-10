echo "[~] Installing dependencies..."

sudo apt-get update && sudo apt-get install -y jq curl

curl -sSfL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" | tar -xz -C /usr/local/bin syft
chmod +x /usr/local/bin/syft

if ! command -v trivy &> /dev/null; then
  echo "[~] Installing Trivy..."
  wget https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb
  sudo dpkg -i trivy_${TRIVY_VERSION}_Linux-64bit.deb
  rm trivy_${TRIVY_VERSION}_Linux-64bit.deb
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
  pipx install semgrep==${SEMGREP_VERSION}
fi

if [ -n "$GHCR_PAT" ]; then
  echo "$GHCR_PAT" | docker login ghcr.io -u "$GITHUB_ACTOR" --password-stdin
else
  echo "[!] GHCR_PAT not set. Skipping Docker auth."
fi