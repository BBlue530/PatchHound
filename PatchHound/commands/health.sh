SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"

source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/utils/health_check.sh"
echo "[i] Backend health check succeeded"