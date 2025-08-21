SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="$( dirname "$SCRIPT_DIR" )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"
source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/system/env_system.sh"

TOKEN=""
PATH_TO_RESOURCES_TOKEN_BASE64=""
LATEST=false
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
        --latest)
            LATEST=true
            shift
            ;;
        --help)
            usage_get_resource
            exit 1
            ;;
        *)
            FILE_NAME+=("$1")
            shift
            ;;
    esac
done

PATH_TO_RESOURCES_TOKEN=$(echo -n "$PATH_TO_RESOURCES_TOKEN_BASE64" | base64 --decode)

if [[ -z "$TOKEN" || -z "$PATH_TO_RESOURCES_TOKEN" ]]; then
    print_message "[!]" "Missing flags" "--token and --path-token are required"
    usage_get_resource
fi

source "$BASE_DIR/utils/health_check.sh"

if [ "${#FILE_NAME[@]}" -eq 0 ]; then
    curl -sSL "$GET_RESOURCES_API_URL" \
        -G \
        --data-urlencode "token=$TOKEN" \
        --data-urlencode "path_to_resources_token=$PATH_TO_RESOURCES_TOKEN" \
        --data-urlencode "latest_resource=$LATEST" \
        --output downloaded_resources
else
    CURL_ARGS_FILE_NAME=()
    for f in "${FILE_NAME[@]}"; do
        CURL_ARGS_FILE_NAME+=(--data-urlencode "file_name=$f")
    done

    curl -sSL "$GET_RESOURCES_API_URL" \
        -G \
        --data-urlencode "token=$TOKEN" \
        --data-urlencode "path_to_resources_token=$PATH_TO_RESOURCES_TOKEN" \
        "${CURL_ARGS_FILE_NAME[@]}" \
        --data-urlencode "latest_resource=$LATEST" \
        --output downloaded_resources
fi

CONTENT_TYPE=$(file --mime-type downloaded_resources | awk '{print $2}')

if [[ "$CONTENT_TYPE" == "application/zip" ]]; then
    print_message "[~]" "Zip received" "Received ZIP archive, extracting..."
    unzip -o downloaded_resources -d downloaded_resources_extracted
    print_message "[+]" "Zip extracted" "Files extracted to ./downloaded_resources_extracted/"
else
    print_message "[+]" "Received file" "Received single file, saved as downloaded_resources"
fi