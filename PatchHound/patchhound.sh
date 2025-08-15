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
                source "$BASE_DIR/commands/get-resource.sh" "$@"
                ;;
            list)
                source "$BASE_DIR/commands/list-resource.sh" "$@"
                ;;
            pdf)
                source "$BASE_DIR/commands/pdf-summary-resource.sh" "$@"
                ;;
            *)
                usage_cli_resource
                ;;
        esac
        ;;
    *)
        usage_cli
        ;;
esac