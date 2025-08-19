SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="$( dirname "$SCRIPT_DIR" )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"
source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/system/env_system.sh"

API_KEY=""
ORG=""
EXP_DAYS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --api-key)
            API_KEY="$2"
            shift 2 
            ;;
        --org)
            ORG="$2" 
            shift 2 
            ;;
        --exp)
            EXP_DAYS="$2"
            shift 2 
            ;;
        *)
    esac
done

if [[ -z "$ORG" || -z "$EXP_DAYS" ]]; then
    print_message "[!]" "Missing flags" "--org and --exp are required"
    usage_create
fi

response=$(curl -s -X POST "$CREATE_TOKEN_API_URL" \
    -d "api_key=$API_KEY" \
    -d "organization=$ORG" \
    -d "expiration_days=$EXP_DAYS")

curl_exit_code=$?
if [ $curl_exit_code -ne 0 ]; then
    print_message "[!]" "Connection fail" "Failed to contact server (curl exit code $curl_exit_code)"
    exit $curl_exit_code
fi

print_message "[i]" "Response from backend" "$response"