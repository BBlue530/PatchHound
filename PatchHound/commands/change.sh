SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"

source "$(dirname "$0")/system/config.sh"

usage() {
    echo "Usage: patchhound change --token <TOKEN_KEY> --ins <enable|disable>"
    exit 1
}

TOKEN=""
INSTRUCTION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)
            TOKEN="$2" 
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
    usage
fi

if [[ "$INSTRUCTION" != "enable" && "$INSTRUCTION" != "disable" ]]; then
    usage
fi

response=$(curl -s -X POST "$KEY_STATUS_API_URL" \
    -F "token=$TOKEN" \
    -F "instructions=$INSTRUCTION")

echo "$response"