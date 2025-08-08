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
    *)
        echo "Usage: patchhound <config|scan|health|create|change> [args]"
        exit 1
        ;;
esac