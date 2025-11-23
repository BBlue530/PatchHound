SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="$( dirname "$SCRIPT_DIR" )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"
source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/system/env_system.sh"

TOKEN=""
PAT_TOKEN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)
            TOKEN="$2"
            shift 2
            ;;
        --pat)
            PAT_TOKEN="$2"
            shift 2
            ;;
        *)
    esac
done

if [ -z "$TOKEN" ]; then
    print_message "[!]" "Missing flag" "--token is required"
    usage_scan
fi

echo "==============================================="
echo "          PatchHound - by BBlue530"
echo "          Version: $PATCHHOUND_VERSION"
echo "==============================================="

source "$BASE_DIR/system/env_variables_scan.sh"
source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/utils/health_check.sh"
source "$BASE_DIR/system/deps.sh"
source "$BASE_DIR/scan/sast_scan.sh"
source "$BASE_DIR/scan/trivy_scan.sh"
source "$BASE_DIR/scan/sbom_generate.sh"
source "$BASE_DIR/scan/sbom_upload.sh"
source "$BASE_DIR/system/vulns_found.sh"
source "$BASE_DIR/display/scan_results.sh"
source "$BASE_DIR/system/cleanup.sh"
source "$BASE_DIR/display/conclusion.sh"

print_message "[+]" "Scan result" "Scan finished successfully"