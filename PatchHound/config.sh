if [ -f "$CONFIG_FILE" ]; then
  source "$CONFIG_FILE"
else
  echo "[-] Config file '$CONFIG_FILE' not found!"
  exit 1
fi

SBOM_SCAN_API_URL="${BASE_URL}/v1/scan-sbom"
HEALTH_CHECK_API_URL="${BASE_URL}/v1/healthcheck"