source "$BASE_DIR/display/print_display.sh"
EXCLUDE_FILE="exclusions.json"

usage_config() {
    echo "Usage:"
    echo "  patchhound config --set <KEY> <VALUE> [<KEY> <VALUE> ...]"
    echo "  patchhound config --get <KEY>"
    echo "  patchhound config --list"
    exit 1
}

usage_change() {
    echo "Usage: patchhound change --token <TOKEN_KEY> --ins <enable|disable>"
    exit 1
}

usage_create() {
    echo "Usage: patchhound create --org <organization> --exp <expiration_days>"
    exit 1
}

usage_get_resource() {
    echo "Usage: $0 --token TOKEN --path-token PATH_TO_RESOURCES_TOKEN [file1 file2 ...]"
    exit 1
}

usage_list_resource() {
    echo "Usage: $0 --token TOKEN --path-token PATH_TO_RESOURCES_TOKEN [file1 file2 ...]"
    exit 1
}

usage_cli_resource() {
    echo "Usage: patchhound resource <get|list> [args]"
    exit 1
}

usage_cli() {
    echo "Usage: patchhound <config|scan|health|create|change|resource|exclude> [args]"
    exit 1
}