source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/system/env_system.sh"
source "$BASE_DIR/exclusion_handling/exclusion_display.sh"

TOKEN=""
REPO=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)
            TOKEN="$2"
            shift 2
            ;;

        --repo)
            REPO="$2"
            shift 2
            ;;
        *)
    esac
done

if [ -z "$REPO" ]; then
    REPO=$(grep "^REPO_NAME=" "$SCAN_PROFILE_CONFIG_FILE" | cut -d= -f2-)
    if [ -z "$REPO" ]; then
      print_message "[!]" "Missing config" "REPO_NAME is missing in scan.config"
      exit 1
    fi
fi

response_and_status=$(curl --connect-timeout 60 --max-time 300 -s -w "\n%{http_code}" \
  -G \
  -d "token=$TOKEN" \
  -d "current_repo=$REPO" \
  "$EXCLUSIONN_GET_API_URL")

curl_exit_code=$?
http_status=$(echo "$response_and_status" | tail -n1)
response_body=$(echo "$response_and_status" | head -n -1)

if [[ "$http_status" = 404 ]]; then
  print_message "[!]" "No exclusions found" "Status Code: $http_status
  $response_body"
  exit 1
fi

if [[ "$http_status" -ne 200 ]]; then
  print_message "[!]" "Backend error" "Status Code: $http_status
  $response_body"
  exit 1
fi

if [ $curl_exit_code -ne 0 ]; then
  print_message "[!]" "Backend error" "Curl failed with exit code: $curl_exit_code"
  exit $curl_exit_code
fi

display_exclusions "$response_body"