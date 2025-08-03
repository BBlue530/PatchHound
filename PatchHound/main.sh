#!/bin/bash
set -e

REPO_DIR="${2:-.}"
CONFIG_FILE="${1:-scan.config}"

source "$(dirname "$0")/config.sh"
source "$(dirname "$0")/health_check.sh"
source "$(dirname "$0")/deps.sh"
source "$(dirname "$0")/sast_scan.sh"
source "$(dirname "$0")/trivy_scan.sh"
source "$(dirname "$0")/sbom_generate.sh"
source "$(dirname "$0")/sbom_upload.sh"
source "$(dirname "$0")/vuln_report.sh"

echo "[+] Scan Finished"