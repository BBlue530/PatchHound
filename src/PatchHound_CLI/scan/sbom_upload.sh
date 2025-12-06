print_message "[~]" "Uploading SBOM to scan service..." ""

COMMIT_AUTHOR="$AUTHOR_NAME <$AUTHOR_EMAIL>"
if [[ ! -f "$EXCLUDE_FILE" ]]; then
    echo '{"exclusions":[]}' > "$EXCLUDE_FILE"
fi

if [ -z "$REPO_NAME" ]; then
    SCAN_PROFILE_CONFIG_FILE="$SCRIPT_DIR/../scan_profile.config"
    REPO_NAME=$(grep "^REPO_NAME=" "$SCAN_PROFILE_CONFIG_FILE" | cut -d= -f2-)
    if [ -z "$REPO_NAME" ]; then
      print_message "[!]" "Missing config" "REPO_NAME is missing"
      exit 1
    fi
fi

if [ -z "$COMMIT_AUTHOR" ]; then
    SCAN_PROFILE_CONFIG_FILE="$SCRIPT_DIR/../scan_profile.config"
    COMMIT_AUTHOR=$(grep "^COMMIT_AUTHOR=" "$SCAN_PROFILE_CONFIG_FILE" | cut -d= -f2-)
    if [ -z "$COMMIT_AUTHOR" ]; then
      print_message "[!]" "Missing config" "COMMIT_AUTHOR is missing"
      exit 1
    fi
fi

if [ -z "$COMMIT_SHA" ]; then
    COMMIT_SHA="Null"
fi

tool_versions_json=$(jq -n \
  --arg syft "$SYFT_VERSION" \
  --arg trivy "$TRIVY_VERSION" \
  --arg semgrep "$SEMGREP_VERSION" \
  '{syft_version: $syft, trivy_version: $trivy, semgrep_version: $semgrep}')

response_and_status=$(curl --connect-timeout 60 --max-time 300 -s -w "\n%{http_code}" \
  -F "sbom=@sbom.cyclonedx.json" \
  -F "sast_report=@sast_report.json" \
  -F "trivy_report=@trivy_report.json" \
  -F "exclusions=@exclusions.json" \
  -F "token=$TOKEN" \
  -F "current_repo=$REPO_NAME" \
  -F "alert_system_webhook=$ALERT_WEBHOOK" \
  -F "commit_sha=$COMMIT_SHA" \
  -F "commit_author=$COMMIT_AUTHOR" \
  -F "tool_versions=$tool_versions_json" \
  "$SBOM_SCAN_API_URL")

curl_exit_code=$?
http_status=$(echo "$response_and_status" | tail -n1)
response_body=$(echo "$response_and_status" | head -n -1)

if [[ "$http_status" -ne 200 ]]; then
  print_message "[!]" "Backend error" "Status Code: $http_status
  $response_body"
  exit 1
fi

if [ $curl_exit_code -ne 0 ]; then
  print_message "[!]" "Backend error" "Curl failed with exit code: $curl_exit_code"
  exit $curl_exit_code
fi

print_message "[+]" "Upload finished" "Upload to backend finished successfully"

echo "$response_body" | jq '.vulns_cyclonedx_json' > vulns.cyclonedx.json
echo "$response_body" | jq '.prio_vulns' > prio_vulns.json
PATH_TO_RESOURCES_TOKEN=$(echo "$response_body" | jq -r '.path_to_resources_token')