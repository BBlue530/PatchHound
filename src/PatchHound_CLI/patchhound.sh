#!/bin/bash
set -e

BASE_DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}" )" )" && pwd )"
COMMAND="$1"
shift || true
source "$BASE_DIR/system/env_system.sh"

case "$COMMAND" in
    config)
        source "$BASE_DIR/commands/config.sh" "$@"
        ;;
    scan)
        source "$BASE_DIR/commands/scan.sh" "$@"
        ;;
    health)
        source "$BASE_DIR/commands/health.sh" "$@"
        ;;
    token-key)
        SUBCOMMAND="$1"
        shift || true
        case "$SUBCOMMAND" in
            create)
                source "$BASE_DIR/commands/token_key_commands/create.sh" "$@"
                ;;
            change)
                source "$BASE_DIR/commands/token_key_commands/change.sh" "$@"
                ;;
            *)
                usage_help
                ;;
        esac
        ;;
    exclude)
        source "$BASE_DIR/commands/exclude.sh" "$@"
        ;;
    resource)
        SUBCOMMAND="$1"
        shift || true
        case "$SUBCOMMAND" in
            get)
                source "$BASE_DIR/commands/resource_commands/resource-get.sh" "$@"
                ;;
            list)
                source "$BASE_DIR/commands/resource_commands/resource-list.sh" "$@"
                ;;
            pdf)
                source "$BASE_DIR/commands/resource_commands/resource-pdf-summary.sh" "$@"
                ;;
            --help)
                usage_cli_resource
                ;;
            *)
                usage_cli_resource
                ;;
        esac
        ;;
    image)
        SUBCOMMAND="$1"
        shift || true
        case "$SUBCOMMAND" in
            sign)
                source "$BASE_DIR/commands/image_commands/image-sign.sh" "$@"
                ;;
            verify)
                source "$BASE_DIR/commands/image_commands/image-verify.sh" "$@"
                ;;
            --help)
                usage_cli_image
                ;;
            *)
                usage_cli_image
                ;;
        esac
        ;;
    base-image)
        SUBCOMMAND="$1"
        shift || true
        case "$SUBCOMMAND" in
            sign)
                source "$BASE_DIR/commands/base_image_commands/base-image-sign.sh" "$@"
                ;;
            verify)
                source "$BASE_DIR/commands/base_image_commands/base-image-verify.sh" "$@"
                ;;
            --help)
                usage_cli_base_image
                ;;
            *)
                usage_cli_base_image
                ;;
        esac
        ;;
    --help)
        usage_help
        ;;
    *)
        usage_help
        ;;
esac