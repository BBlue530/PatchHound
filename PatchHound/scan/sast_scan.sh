print_message "[~]" "Running SAST scan..." ""
semgrep --config=p/security-audit --config=p/ci --json "$REPO_DIR" > "sast_report.json"