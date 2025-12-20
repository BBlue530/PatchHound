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

PATCHHOUND_VERSION="0.1.15"

SBOM_SCAN_API_URL="${BASE_URL}/v1/scan-sbom"
HEALTH_CHECK_API_URL="${BASE_URL}/v1/health-check"
KEY_STATUS_API_URL="${BASE_URL}/v1/change-key-status"
CREATE_TOKEN_API_URL="${BASE_URL}/v1/create-token-key"
GET_RESOURCES_API_URL="${BASE_URL}/v1/get-resources"
LIST_RESOURCES_API_URL="${BASE_URL}/v1/list-resources"
PDF_SUMMARY_API_URL="${BASE_URL}/v1/generate-pdf"
IMAGE_SIGN_API_URL="${BASE_URL}/v1/sign-image"
IMAGE_VERIFY_API_URL="${BASE_URL}/v1/verify-image"
BASE_IMAGE_SIGN_API_URL="${BASE_URL}/v1/sign-base-image"
BASE_IMAGE_VERIFY_API_URL="${BASE_URL}/v1/verify-base-image"