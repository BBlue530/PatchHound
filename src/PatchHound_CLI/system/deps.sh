print_message "[~]" "Installing dependencies..." ""

SYFT_VERSION="1.38.0"
TRIVY_VERSION="0.56.2"
SEMGREP_VERSION="1.95.0"

BASE_DIR_DEPS="$HOME/local/bin/patchhound"
BASE_DIR_BIN="$BASE_DIR_DEPS/bin"
BASE_DIR_VENV="$BASE_DIR_DEPS/venv/bin"

SYFT_OUTPUT=$("$BASE_DIR_BIN/syft" version 2>/dev/null | tr -d 'v' || echo "")
TRIVY_OUTPUT=$("$BASE_DIR_BIN/trivy" version 2>/dev/null | awk '{print $2}' || echo "")
SEMGREP_OUTPUT=$(semgrep --version 2>/dev/null | awk '{print $2}' || echo "")

echo "SEMGREP_OUTPUT"
echo "$SEMGREP_OUTPUT"

echo "TRIVY_OUTPUT"
echo "$TRIVY_OUTPUT"

sudo mkdir -p "$BASE_DIR_BIN"
sudo mkdir -p "$BASE_DIR_VENV"

if [[ "$SYFT_OUTPUT" != *"$SYFT_VERSION"* ]]; then
  print_message "[~]" "Installing syft $SYFT_VERSION..." ""
  sudo apt-get update && sudo apt-get install -y jq curl

  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "$BASE_DIR_BIN" "v$SYFT_VERSION"
fi

if [[ "$TRIVY_OUTPUT" != *"$TRIVY_VERSION"* ]]; then
  if [ "$TRIVY_SCAN" = "true" ]; then
    print_message "[~]" "Installing Trivy..." ""
    wget https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz
    tar -xzf trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz
    mv trivy "$BASE_DIR_BIN/trivy"
  fi
fi

if [ "$SAST_SCAN" = "true" ]; then
  if ! check_command pipx; then
    print_message "[~]" "Installing pipx..." ""
    sudo apt update
    sudo apt install -y pipx
    python3 -m pipx ensurepath
  fi
  if [[ "$SEMGREP_OUTPUT" != *"$SEMGREP_VERSION" ]]; then
    print_message "[~]" "Installing semgrep..." ""
    pipx install semgrep==$SEMGREP_VERSION --force
    export PATH="$PATH:$HOME/.local/bin"
  fi
fi