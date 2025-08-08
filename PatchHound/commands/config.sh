CONFIG_FILE="scan.config"

usage_config() {
    echo "Usage:"
    echo "  patchhound config set <KEY> <VALUE> [<KEY> <VALUE> ...]"
    echo "  patchhound config get <KEY>"
    echo "  patchhound config list"
    exit 1
}

case "$1" in
    set)
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
    get)
        if [[ -z "$2" ]]; then usage_config; fi
        grep "^$2=" "$CONFIG_FILE" | cut -d= -f2-
        ;;
    list)
        cat "$CONFIG_FILE"
        ;;
    *)
        usage_config
        ;;
esac