#!/bin/bash
set -e

COMMAND="$1"
shift || true

case "$COMMAND" in
    config)
        source "$(dirname "$0")/commands/config.sh" "$@"
        ;;
    scan)
        source "$(dirname "$0")/commands/scan.sh" "$@"
        ;;
    health)
        source "$(dirname "$0")/commands/health.sh" "$@"
        ;;
    create)
        source "$(dirname "$0")/commands/create.sh" "$@"
        ;;
    change)
        source "$(dirname "$0")/commands/change.sh" "$@"
        ;;
    resource)
        SUBCOMMAND="$1"
        shift || true
        case "$SUBCOMMAND" in
            get)
                source "$(dirname "$0")/commands/get-resource.sh" "$@"
                ;;
            list)
                source "$(dirname "$0")/commands/list-resource.sh" "$@"
                ;;
            *)
                echo "Usage: patchhound resource <get|list> [args]"
                exit 1
                ;;
        esac
        ;;
    *)
        echo "Usage: patchhound <config|scan|health|create|change|resource> [args]"
        exit 1
        ;;
esac