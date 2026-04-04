if [ -f "$CONFIG_FILE" ]; then
  source "$CONFIG_FILE"
else
  print_message "[!]" "Config missing" "Config file '$CONFIG_FILE' not found!"
  exit 1
fi

if [ -z "$BASE_URL" ]; then
  print_message "[!]" "BASE_URL missing" "BASE_URL is not set in config file"
  exit 1
fi

DEFAULT_SAST_RULESETS=(--config=p/security-audit --config=p/ci)

TRIVY_FS_SCANNERS="vuln,secret,misconfig"
TRIVY_IMAGE_SCANNERS="vuln,secret,misconfig"

PATCHHOUND_VERSION="0.1.47"

PATCHHOUND_SCAN_DATA="PatchHound_Scan_Data/"

source "$BASE_DIR/system/set_endpoints.sh"