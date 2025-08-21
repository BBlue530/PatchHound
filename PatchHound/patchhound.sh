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
    create)
        source "$BASE_DIR/commands/create.sh" "$@"
        ;;
    change)
        source "$BASE_DIR/commands/change.sh" "$@"
        ;;
    exclude)
        source "$BASE_DIR/commands/exclude.sh" "$@"
        ;;
    resource)
        SUBCOMMAND="$1"
        shift || true
        case "$SUBCOMMAND" in
            get)
                source "$BASE_DIR/commands/resource-get.sh" "$@"
                ;;
            list)
                source "$BASE_DIR/commands/resource-list.sh" "$@"
                ;;
            pdf)
                source "$BASE_DIR/commands/resource-pdf-summary.sh" "$@"
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
                source "$BASE_DIR/commands/image-sign.sh" "$@"
                ;;
            verify)
                source "$BASE_DIR/commands/image-verify.sh" "$@"
                ;;
            --help)
                usage_cli_image
                ;;
            *)
                usage_cli_image
                ;;
        esac
        ;;
    --help)
        usage_help
        ;;
    *)
        usage_cli
        ;;
esac