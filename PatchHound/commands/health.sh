SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"

source "$(dirname "$0")/system/config.sh"
source "$(dirname "$0")/utils/health_check.sh"
echo "[i] Backend health check succeeded"