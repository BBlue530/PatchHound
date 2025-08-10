SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"

source "$(dirname "$0")/system/config.sh"¨
source "$(dirname "$0")/utils/health_check.sh"

usage() {
    echo "Usage: $0 --token TOKEN --path-token PATH_TO_RESOURCES_TOKEN [file1 file2 ...]"
    exit 1
}

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
            FILE_NAME+=("$1")
            shift
            ;;
    esac
done

PATH_TO_RESOURCES_TOKEN=$(echo -n "$PATH_TO_RESOURCES_TOKEN_BASE64" | base64 --decode)

if [[ -z "$TOKEN" || -z "$PATH_TO_RESOURCES_TOKEN" ]]; then
    echo "Error: --token and --path-token are required"
    usage
fi

if [ "${#FILE_NAME[@]}" -eq 0 ]; then
    curl -sSL "$GET_RESOURCES_API_URL" \
        -G \
        --data-urlencode "token=$TOKEN" \
        --data-urlencode "path_to_resources_token=$PATH_TO_RESOURCES_TOKEN" \
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
        --output downloaded_resources
fi

CONTENT_TYPE=$(file --mime-type downloaded_resources | awk '{print $2}')

if [[ "$CONTENT_TYPE" == "application/zip" ]]; then
    echo "[+] Received ZIP archive, extracting..."
    unzip -o downloaded_resources -d downloaded_resources_extracted
    echo "[+] FILE_NAME extracted to ./downloaded_resources_extracted/"
else
    echo "[+] Received single file, saved as downloaded_resources"
fi