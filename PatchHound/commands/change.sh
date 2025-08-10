CONFIG_FILE="scan.config"

source "$(dirname "$0")/config.sh"

usage_change() {
    echo "Usage: patchhound change token <TOKEN_KEY> <enable|disable>"
    exit 1
}

if [[ "$1" != "token" ]]; then
    usage_change
fi

TOKEN="$2"
INSTRUCTION="$3"

if [[ -z "$TOKEN" || -z "$INSTRUCTION" ]]; then
    usage_change
fi

if [[ "$INSTRUCTION" != "enable" && "$INSTRUCTION" != "disable" ]]; then
    usage_change
fi

response=$(curl -s -X POST "$KEY_STATUS_API_URL" \
    -F "token=$TOKEN" \
    -F "instructions=$INSTRUCTION")

echo "$response"