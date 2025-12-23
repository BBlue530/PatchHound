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
        --set-config)
            if (( $# < 3 )) || (( ($# - 1) % 2 != 0 )); then
                usage_config
            fi
            shift
            while (( $# > 0 )) && [[ "$1" != --* ]]; do
                KEY="$1"
                VALUE="$2"
                if grep -q "^${KEY}=" "$CONFIG_FILE"; then
                    print_message "[+]" "Config Value Changed For Environment" "Set $KEY=***"
                    export "$KEY=$VALUE"
                    
                elif grep -q "^${KEY}=" "$SCAN_PROFILE_CONFIG_FILE"; then
                    print_message "[+]" "Config Value Changed For Environment" "Set $KEY=***"
                    export "$KEY=$VALUE"

                else
                    print_message "[!]" "Key not found" "${KEY} does not exist in config"
                fi
                shift 2
            done
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