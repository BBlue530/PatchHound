#!/bin/bash
set -e

REPO_DIR="."
CONFIG_FILE="scan.config"

source "$(dirname "$0")/config.sh"
source "$(dirname "$0")/health_check.sh"
source "$(dirname "$0")/deps.sh"
source "$(dirname "$0")/sast_scan.sh"
source "$(dirname "$0")/trivy_scan.sh"
source "$(dirname "$0")/sbom_generate.sh"
source "$(dirname "$0")/sbom_upload.sh"
source "$(dirname "$0")/scan_results.sh"
source "$(dirname "$0")/vulns_found.sh"
source "$(dirname "$0")/conclusion.sh"

echo "[+] Scan Finished"