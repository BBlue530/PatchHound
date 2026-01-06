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

PATCHHOUND_VERSION="0.1.36"

SBOM_SCAN_API_URL="${BASE_URL}/v1/scan-sbom"
HEALTH_CHECK_API_URL="${BASE_URL}/v1/health-check"

# Token key command endpoints
CREATE_TOKEN_API_URL="${BASE_URL}/v1/create-token-key"
KEY_STATUS_API_URL="${BASE_URL}/v1/change-key-status"
REMOVE_TOKEN_API_URL="${BASE_URL}/v1/remove-token-key"
LIST_TOKEN_API_URL="${BASE_URL}/v1/list-token-key"

# Resource command endpoints
GET_RESOURCES_API_URL="${BASE_URL}/v1/get-resources"
LIST_RESOURCES_API_URL="${BASE_URL}/v1/list-resources"
PDF_SUMMARY_API_URL="${BASE_URL}/v1/generate-pdf"

# Image command endpoints
IMAGE_SIGN_API_URL="${BASE_URL}/v1/sign-image"
IMAGE_VERIFY_API_URL="${BASE_URL}/v1/verify-image"

# Base image command endpoints
BASE_IMAGE_SIGN_API_URL="${BASE_URL}/v1/sign-base-image"
BASE_IMAGE_VERIFY_API_URL="${BASE_URL}/v1/verify-base-image"