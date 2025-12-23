source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/system/env_system.sh"

API_KEY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --api-key)
            API_KEY="$2"
            shift 2 
            ;;
        --help)
            usage_list
            exit 1
            ;;
        *)
    esac
done

if [[ -z "$API_KEY" ]]; then
    print_message "[!]" "Missing flags" "--api-key and is required"
    usage_list
fi

response=$(curl -s -X POST "$LIST_TOKEN_API_URL" \
    -d "api_key=$API_KEY")

curl_exit_code=$?
if [ $curl_exit_code -ne 0 ]; then
    print_message "[!]" "Connection fail" "Failed to contact server (curl exit code $curl_exit_code)"
    exit $curl_exit_code
fi

if echo "$response" | jq -e 'type == "array"' >/dev/null 2>&1; then
    print_message "[i]" "Response from backend" ""

    echo "$response" | jq -c '.[]' | while read -r result; do
        token_key=$(echo "$result" | jq -r '.token_key')
        organization=$(echo "$result" | jq -r '.organization')
        expiration_date=$(echo "$result" | jq -r '.expiration_date')
        enabled=$(echo "$result" | jq -r '.enabled')

        echo "Token key:         $token_key"
        echo "Organization:      $organization"
        echo "Expiration date:   $expiration_date"
        echo "Enabled:           $enabled"
        echo ""
    done
else
    print_message "[!]" "Response from backend" "$response"
fi