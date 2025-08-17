print_message "[~]" "Signing image with sign service..." ""

COMMIT_AUTHOR="$AUTHOR_NAME <$AUTHOR_EMAIL>"

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
    print_message "[~]" "Image not found locally, pulling $IMAGE..."
    docker pull "$IMAGE"
fi

IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE")

response_and_status=$(curl --connect-timeout 60 --max-time 300 -s -w "\n%{http_code}" \
  -F "token=$TOKEN" \
  -F "current_repo=$REPO_NAME" \
  -F "alert_system_webhook=$ALERT_WEBHOOK" \
  -F "commit_sha=$COMMIT_SHA" \
  -F "commit_author=$COMMIT_AUTHOR" \
  -F "image=$IMAGE_DIGEST" \
  "$IMAGE_SIGN_API_URL")

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

print_message "[+]" "Signing finished" "Signing of image with backend finished successfully"

PATH_TO_RESOURCES_TOKEN=$(echo "$response_body" | jq -r '.path_to_resources_token')

PATH_TO_RESOURCES_TOKEN_BASE64=$(printf "%s" "$PATH_TO_RESOURCES_TOKEN" | base64 -w 0)

print_message "[i]" "Path to signature:" "$PATH_TO_RESOURCES_TOKEN_BASE64"