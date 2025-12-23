SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CONFIG_FILE="$BASE_DIR/scan.config"
source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/system/env_system.sh"

TOKEN=""
PATH_TO_RESOURCES_TOKEN_BASE64=""
LATEST=false
REPO_RESOURCES=false

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
        --latest)
            LATEST=true
            shift
            ;;
        --repo-resources)
            REPO_RESOURCES=true
            shift
            ;;
        --help)
            usage_list_resource
            exit 1
            ;;
        *)
    esac
done

PATH_TO_RESOURCES_TOKEN=$(echo -n "$PATH_TO_RESOURCES_TOKEN_BASE64" | base64 --decode)

if [[ -z "$TOKEN" || -z "$PATH_TO_RESOURCES_TOKEN" ]]; then
    print_message "[!]" "Missing flags" "--token and --path-token are required"
    usage_list_resource
fi

source "$BASE_DIR/utils/health_check.sh"

RESPONSE=$(curl -sSL "$LIST_RESOURCES_API_URL" \
        -G \
        --data-urlencode "token=$TOKEN" \
        --data-urlencode "path_to_resources_token=$PATH_TO_RESOURCES_TOKEN" \
        --data-urlencode "repo_resources=$REPO_RESOURCES" \
        --data-urlencode "latest_resource=$LATEST")

print_message "[+]" "Resources found" "Files in resource directory:"
mapfile -t FILES < <(echo "$RESPONSE" | grep -oP '"files":\s*\[\K[^\]]+' | tr -d '"' | tr ',' '\n' | sed 's/^\s*//;s/\s*$//')

for file in "${FILES[@]}"; do
    echo "File: $file"
done