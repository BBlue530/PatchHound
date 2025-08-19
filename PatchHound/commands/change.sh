SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="$( dirname "$SCRIPT_DIR" )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"
source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/system/env_system.sh"

TOKEN=""
API_KEY=""
INSTRUCTION=""
INSTRUCTION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)
            TOKEN="$2" 
            shift 2 
            ;;
        --api-key)
            API_KEY="$2"
            shift 2 
            ;;
        --ins)
            INSTRUCTION="$2"
            shift 2 
            ;;
        *)
    esac
done

if [[ -z "$TOKEN" || -z "$INSTRUCTION" ]]; then
    usage_change
fi

if [[ "$INSTRUCTION" != "enable" && "$INSTRUCTION" != "disable" ]]; then
    usage_change
fi

source "$BASE_DIR/utils/health_check.sh"

response=$(curl -s -X POST "$KEY_STATUS_API_URL" \
    -F "api_key=$API_KEY" \
    -F "token=$TOKEN" \
    -F "instructions=$INSTRUCTION")

print_message "[i]" "Response from backend" "$response"