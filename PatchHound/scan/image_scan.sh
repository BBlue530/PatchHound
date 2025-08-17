print_message "[~]" "Uploading image to scan service..." ""

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

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker pull "$IMAGE"
fi

IMAGE_TAR="image.tar"
docker save "$IMAGE" -o "$IMAGE_TAR"

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
  -F "image=@$IMAGE_TAR" \
  "$IMAGE_SCAN_API_URL")

curl_exit_code=$?
http_status=$(echo "$response_and_status" | tail -n1)
response_body=$(echo "$response_and_status" | head -n -1)

rm -f "$IMAGE_TAR"

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

PATH_TO_RESOURCES_TOKEN=$(echo "$response_body" | jq -r '.path_to_resources_token')