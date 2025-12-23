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
    echo "Usage:"
    echo "  patchhound token-key change --api-key <API_KEY> --token <TOKEN_KEY> --ins <enable|disable>"
    exit 1
}

usage_create() {
    echo "Usage:"
    echo "  patchhound token-key create --api-key <API_KEY> --org <ORGANIZATION> --exp <EXPIRATION_DAYS>"
    exit 1
}

usage_remove() {
    echo "Usage:"
    echo "  patchhound token-key remove --api-key <API_KEY> --token <TOKEN_KEY>"
    exit 1
}

usage_get_resource() {
    echo "Usage:"
    echo "  patchhound resource get --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN>"
    echo "  patchhound resource get --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> [file1 file2 ...]"
    echo "  patchhound resource get --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> --latest"
    exit 1
}

usage_list_resource() {
    echo "Usage:"
    echo "  patchhound resource list --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN>"
    echo "  patchhound resource get --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> --latest"
    exit 1
}

usage_cli_resource() {
    echo "Usage:"
    echo "  patchhound resource get --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN>"
    echo "  patchhound resource get --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> [file1 file2 ...]"
    echo "  patchhound resource list --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN>"
    exit 1
}

usage_exclude() {
    echo "Usage:"
    echo "  patchhound exclude --cve <CVE_ID> --comment <COMMENT_FOR_EXCLUSION>"
    echo "  patchhound exclude --list"
    echo "  patchhound exclude --remove <CVE_ID>"
    exit 1
}

usage_cli_image() {
    echo "Usage:"
    echo "  patchhound image sign --image <image_name> --token <token>"
    echo "  patchhound image verify --image <image_name> --token <token> --path-token <path_to_resources_token>"
    exit 1
}

usage_cli_base_image() {
    echo "Usage:"
    echo "  patchhound base-image sign --image <image_name> --token <token>"
    echo "  patchhound base-image verify --image <image_name> --token <token>"
    exit 1
}

usage_sign_image() {
    echo "Usage:"
    echo "  patchhound image sign --image <IMAGE_NAME> --token <TOKEN> --pat <PAT_TOKEN(needed for private images)>"
    exit 1
}

usage_sign_base_image() {
    echo "Usage:"
    echo "  patchhound base-image sign --image <IMAGE_NAME> --token <TOKEN> --pat <PAT_TOKEN(needed for private images)>"
    exit 1
}

usage_verify_image() {
    echo "Usage:"
    echo "  patchhound image verify --image <IMAGE_NAME> --token <TOKEN> --pat <PAT_TOKEN(needed for private images)> --path-token <PATH_TO_RESOURCES_TOKEN>"
    exit 1
}

usage_scan() {
    echo "Usage:"
    echo "  patchhound scan --token <token>"
    echo "  patchhound scan --token <token> --pat <pat_token(needed for private images)>"
    exit 1
}

usage_health() {
    echo "Usage:"
    echo "  patchhound health --token <TOKEN_KEY>"
    exit 1
}

usage_pdf_summary() {
    echo "Usage:"
    echo "  patchhound resource pdf --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> "
    exit 1
}

usage_help() {
    echo "PatchHound CLI"
    echo ""
    echo "Usage:"
    echo "  patchhound <command> [options]"
    echo ""
    echo "Commands:"
    echo "  config                 Manage PatchHound config (set/get/list)"
    echo "  token-key change       Enable or disable token keys"
    echo "  token-key create       Create new token keys"
    echo "  token-key remove       Remove token keys"
    echo "  resource               Get or list repository resources"
    echo "  exclude                Manage vulnerability exclusions (add/list/remove)"
    echo "  scan                   Run a new scan"
    echo "  sign                   Sign container images"
    echo "  verify                 Verify signed container images"
    echo "  health                 Perform health check of the API"
    echo "  resource pdf           Generate PDF summary reports"
    echo "  --help                 Show this help message"
    echo ""
    echo "Use 'patchhound <command> --help' for more information on a specific command."
    exit 1
}