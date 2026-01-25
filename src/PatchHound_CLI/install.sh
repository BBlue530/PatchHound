#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PATCHHOUND_SCRIPT="$SCRIPT_DIR/patchhound.sh"

chmod +x "$PATCHHOUND_SCRIPT"

if [ "$(id -u)" -eq 0 ]; then
    ln -sf "$PATCHHOUND_SCRIPT" /usr/local/bin/patchhound
    echo "[+] Installed PatchHound globally (root user)"
else
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo ln -sf "$PATCHHOUND_SCRIPT" /usr/local/bin/patchhound
        echo "[+] Installed PatchHound globally"
    else
        mkdir -p "$HOME/.local/bin"
        ln -sf "$PATCHHOUND_SCRIPT" "$HOME/.local/bin/patchhound"
        echo "$HOME/.local/bin" >> "$GITHUB_PATH" 2>/dev/null || true
        echo "[+] Installed PatchHound for current user at $HOME/.local/bin/patchhound"
    fi
fi
