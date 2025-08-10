SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"

source "$(dirname "$0")/config.sh"
source "$(dirname "$0")/health_check.sh"
echo "[i] Backend health check succeeded"