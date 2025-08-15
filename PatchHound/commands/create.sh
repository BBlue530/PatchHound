SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="$( dirname "$SCRIPT_DIR" )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"
source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/system/env_system.sh"

if [[ "$1" != "org" ]]; then usage_create; fi

org=""
exp_days=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --org)
            org="$2" 
            shift 2 
            ;;
        --exp)
            exp_days="$2"
            shift 2 
            ;;
        *)
    esac
done

if [[ -z "$org" || -z "$exp_days" ]]; then
    print_message "[!]" "Missing flags" "--org and --exp are required"
    usage_create
fi

response=$(curl -s -X POST "$CREATE_TOKEN_API_URL" \
    -d "organization=$org" \
    -d "expiration_days=$exp_days")

curl_exit_code=$?
if [ $curl_exit_code -ne 0 ]; then
    print_message "[!]" "Connection fail" "Failed to contact server (curl exit code $curl_exit_code)"
    exit $curl_exit_code
fi

print_message "[i]" "Response from backend" "$response"