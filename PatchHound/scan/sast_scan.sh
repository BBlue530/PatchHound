print_message "[~]" "Running SAST scan..." ""
semgrep --config=p/security-audit --config=p/ci --json "$TARGET" > "sast_report.json"