source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/system/env_system.sh"

API_KEY=""
TOKEN_KEY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --api-key)
            API_KEY="$2"
            shift 2 
            ;;
        --token)
            TOKEN_KEY="$2" 
            shift 2 
            ;;
        --help)
            usage_remove
            exit 1
            ;;
        *)
    esac
done

if [[ -z "$API_KEY" || -z "$TOKEN_KEY" ]]; then
    print_message "[!]" "Missing flags" "--api-key and --token are required"
    usage_remove
fi

response=$(curl -s -X POST "$REMOVE_TOKEN_API_URL" \
    -d "api_key=$API_KEY" \
    -d "token_key=$TOKEN_KEY")

curl_exit_code=$?
if [ $curl_exit_code -ne 0 ]; then
    print_message "[!]" "Connection fail" "Failed to contact server (curl exit code $curl_exit_code)"
    exit $curl_exit_code
fi

print_message "[i]" "Response from backend" "$response"