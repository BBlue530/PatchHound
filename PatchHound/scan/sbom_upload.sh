echo "[~] Uploading SBOM to scan service..."

COMMIT_AUTHOR="$AUTHOR_NAME <$AUTHOR_EMAIL>"

response_and_status=$(curl --connect-timeout 60 --max-time 300 -s -w "\n%{http_code}" \
  -F "sbom=@sbom.cyclonedx.json" \
  -F "sast_report=@sast_report.json" \
  -F "trivy_report=@trivy_report.json" \
  -F "token=$TOKEN" \
  -F "current_repo=$REPO_NAME" \
  -F "alert_system_webhook=$ALERT_WEBHOOK" \
  -F "commit_sha=$COMMIT_SHA" \
  -F "commit_author=$COMMIT_AUTHOR" \
  "$SBOM_SCAN_API_URL")

curl_exit_code=$?
http_status=$(echo "$response_and_status" | tail -n1)
response_body=$(echo "$response_and_status" | head -n -1)

if [[ "$http_status" -ne 200 ]]; then
  echo "[!] Error: Status Code: $http_status"
  echo "$response_body"
  exit 1
fi

if [ $curl_exit_code -ne 0 ]; then
  echo "[!] Error: curl failed with exit code $curl_exit_code"
  exit $curl_exit_code
fi

echo "[+] Upload to scan service finished"

echo "$response_body" | jq '.vulns_cyclonedx_json' > vulns.cyclonedx.json
echo "$response_body" | jq '.prio_vulns' > prio_vulns.json
PATH_TO_RESOURCES_TOKEN=$(echo "$response_body" | jq -r '.path_to_resources_token')