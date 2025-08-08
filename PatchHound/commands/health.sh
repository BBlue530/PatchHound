CONFIG_FILE="${1:-scan.config}"

source "$(dirname "$0")/config.sh"
source "$(dirname "$0")/health_check.sh"
echo "[i] Backend health check succeeded"