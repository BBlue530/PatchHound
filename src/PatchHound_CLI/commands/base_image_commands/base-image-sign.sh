SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="$( dirname "$SCRIPT_DIR" )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"
source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/system/env_system.sh"

IMAGE=""
TOKEN=""
PAT_TOKEN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)
            IMAGE="$2"
            shift 2
            ;;
        --token)
            TOKEN="$2"
            shift 2
            ;;
        --pat)
            PAT_TOKEN="$2"
            shift 2
            ;;
        --help)
            usage_sign_base_image
            exit 1
            ;;
        *)
    esac
done

if [[ -z "$TOKEN" ]]; then
    print_message "[!]" "Missing flags" "--token is required"
    usage_sign_base_image
fi

echo "==============================================="
echo "          PatchHound - by BBlue530"
echo "          Version: $PATCHHOUND_VERSION"
echo "==============================================="

source "$BASE_DIR/system/env_variables_scan.sh"
source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/utils/health_check.sh"
source "$BASE_DIR/scan/base_image_sign.sh"