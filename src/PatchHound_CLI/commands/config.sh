source "$BASE_DIR/system/config.sh"
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
                print_message "[+]" "Config Value Changed" "Set $KEY=$VALUE in $CONFIG_FILE"
                
            elif grep -q "^${KEY}=" "$SCAN_PROFILE_CONFIG_FILE"; then
                sed -i "s|^${KEY}=.*|${KEY}=${VALUE}|" "$SCAN_PROFILE_CONFIG_FILE"
                print_message "[+]" "Config Value Changed" "Set $KEY=$VALUE in $SCAN_PROFILE_CONFIG_FILE"

            else
                print_message "[!]" "Key not found" "${KEY} does not exist in config"
            fi
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
                print_message "[+]" "Config Value Changed" "Set $KEY=*** in $CONFIG_FILE"
                
            elif grep -q "^${KEY}=" "$SCAN_PROFILE_CONFIG_FILE"; then
                sed -i "s|^${KEY}=.*|${KEY}=${VALUE}|" "$SCAN_PROFILE_CONFIG_FILE"
                print_message "[+]" "Config Value Changed" "Set $KEY=*** in $SCAN_PROFILE_CONFIG_FILE"

            else
                print_message "[!]" "Key not found" "${KEY} does not exist in config"
            fi
            shift 2
        done
        ;;
    --get)
        if [[ -z "$2" ]]; then usage_config; fi
        KEY="$2"
        VALUE=$(grep "^${KEY}=" "$CONFIG_FILE" | cut -d= -f2-)
        if [[ -n "$VALUE" ]]; then
            print_message "[+]" "$KEY=$VALUE" ""

        else
            VALUE=$(grep "^${KEY}=" "$SCAN_PROFILE_CONFIG_FILE" | cut -d= -f2-)
            if [[ -n "$VALUE" ]]; then
                print_message "[+]" "$KEY=$VALUE" ""

            else
                print_message "[!]" "Key not found" "${KEY} does not exist in config"
            fi
        fi
        ;;
    --list)
        cat "$CONFIG_FILE"
        cat "$SCAN_PROFILE_CONFIG_FILE"
        ;;
    --help)
        usage_config
        exit 1
        ;;
    *)
        usage_config
        ;;
esac