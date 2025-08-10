if [ "$SCAN_IMAGE" = "true" ]; then
    echo "[~] Running Trivy scan on image..."
    trivy image --format json -o trivy_report.json "$TARGET"
else
    echo "[~] Running Trivy scan on source repo..."
    trivy fs --scanners vuln,secret,config --format json -o trivy_report.json "$TARGET"
fi