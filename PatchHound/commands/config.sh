SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="$( dirname "$SCRIPT_DIR" )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"
source "$BASE_DIR/system/env_system.sh"

case "$1" in
    --set)
        if (( $# < 3 )) || (( ($# - 1) % 2 != 0 )); then
            usage_config
        fi
        shift
        while (( $# > 0 )); do
            KEY="$1"
            VALUE="$2"
            if grep -q "^${KEY}=" "$CONFIG_FILE"; then
                sed -i "s|^${KEY}=.*|${KEY}=${VALUE}|" "$CONFIG_FILE"
            else
                echo "${KEY}=${VALUE}" >> "$CONFIG_FILE"
            fi
            echo "[+] Set $KEY=$VALUE"
            shift 2
        done
        ;;
    --set-secret)
        if (( $# < 3 )) || (( ($# - 1) % 2 != 0 )); then
            usage_config
        fi
        shift
        while (( $# > 0 )); do
            KEY="$1"
            VALUE="$2"
            if grep -q "^${KEY}=" "$CONFIG_FILE"; then
                sed -i "s|^${KEY}=.*|${KEY}=${VALUE}|" "$CONFIG_FILE"
            else
                echo "${KEY}=${VALUE}" >> "$CONFIG_FILE"
            fi
            echo "[+] Set $KEY=***"
            shift 2
        done
        ;;
    --get)
        if [[ -z "$2" ]]; then usage_config; fi
        grep "^$2=" "$CONFIG_FILE" | cut -d= -f2-
        ;;
    --list)
        cat "$CONFIG_FILE"
        ;;
    *)
        usage_config
        ;;
esac