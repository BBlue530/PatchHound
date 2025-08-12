SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="$( dirname "$SCRIPT_DIR" )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"
source "$BASE_DIR/system/env_system.sh"
source "$BASE_DIR/utils/health_check.sh"

TOKEN=""
PATH_TO_RESOURCES_TOKEN_BASE64=""
FILE_NAME=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)
            TOKEN="$2"
            shift 2
            ;;
        --path-token)
            PATH_TO_RESOURCES_TOKEN_BASE64="$2"
            shift 2
            ;;
        *)
    esac
done

PATH_TO_RESOURCES_TOKEN=$(echo -n "$PATH_TO_RESOURCES_TOKEN_BASE64" | base64 --decode)

if [[ -z "$TOKEN" || -z "$PATH_TO_RESOURCES_TOKEN" ]]; then
    print_message "[!]" "Missing flags" "--token and --path-token are required"
    usage_list_resource
fi

RESPONSE=$(curl -sSL "$LIST_RESOURCES_API_URL" \
        -G \
        --data-urlencode "token=$TOKEN" \
        --data-urlencode "path_to_resources_token=$PATH_TO_RESOURCES_TOKEN")

print_message "[+]" "Resources found" "Files in resource directory:"
mapfile -t FILES < <(echo "$RESPONSE" | grep -oP '"files":\s*\[\K[^\]]+' | tr -d '"' | tr ',' '\n' | sed 's/^\s*//;s/\s*$//')

for file in "${FILES[@]}"; do
    echo "File: $file"
done