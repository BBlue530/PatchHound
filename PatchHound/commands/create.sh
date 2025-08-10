SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"

source "$(dirname "$0")/config.sh"

usage_create() {
    echo "Usage: patchhound create org <organization> exp <expiration_days>"
    exit 1
}

if [[ "$1" != "org" ]]; then usage_create; fi

org=""
exp_days=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        org) org="$2"; shift 2 ;;
        exp) exp_days="$2"; shift 2 ;;
        *) echo "[!] Unknown argument: $1"; usage_create ;;
    esac
done

if [[ -z "$org" || -z "$exp_days" ]]; then
    echo "[!] Missing org/exp"
    usage_create
fi

response=$(curl -s -X POST "$CREATE_TOKEN_API_URL" \
    -d "organization=$org" \
    -d "expiration_days=$exp_days")

curl_exit_code=$?
if [ $curl_exit_code -ne 0 ]; then
    echo "[!] Failed to contact server (curl exit code $curl_exit_code)"
    exit $curl_exit_code
fi

echo "$response"