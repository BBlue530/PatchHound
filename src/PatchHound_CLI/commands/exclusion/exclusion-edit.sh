source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/system/env_system.sh"
source "$BASE_DIR/exclusion_handling/exclusion_display.sh"
source "$BASE_DIR/exclusion_handling/exclusion_edit_entry.sh"

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
get_request_http_status=$(echo "$response_and_status" | tail -n1)
response_body=$(echo "$response_and_status" | head -n -1)

if [[ "$get_request_http_status" = 404 ]]; then
  print_message "[+]" "No exclusions found" "Status Code: $get_request_http_status"
  exclusion_data='{"exclusions":[]}'
  response_body="$exclusion_data"
  edit_exclusions
else

  if [[ "$get_request_http_status" -ne 200 ]]; then
    print_message "[!]" "Backend error" "Status Code: $get_request_http_status
    $response_body"
    exit 1
  fi

  if [ $curl_exit_code -ne 0 ]; then
    print_message "[!]" "Backend error" "Curl failed with exit code: $curl_exit_code"
    exit $curl_exit_code
  fi
fi

display_exclusions "$response_body"

edit_exclusions

TMP_EXCLUSION_FILE=$(mktemp)
echo "$response_body" > "$TMP_EXCLUSION_FILE"

response_and_status=$(curl --connect-timeout 60 --max-time 300 -s -w "\n%{http_code}" \
  -X POST \
  -F "token=$TOKEN" \
  -F "current_repo=$REPO" \
  -F "new_exclusion_file=@$TMP_EXCLUSION_FILE" \
  "$EXCLUSIONN_POST_API_URL")

curl_exit_code=$?
post_request_http_status=$(echo "$response_and_status" | tail -n1)
response_body=$(echo "$response_and_status" | head -n -1)

if [[ "$post_request_http_status" -ne 200 ]]; then
  print_message "[!]" "Backend error" "Status Code: $post_request_http_status
  $response_body"
  exit 1
fi

if [ $curl_exit_code -ne 0 ]; then
  print_message "[!]" "Backend error" "Curl failed with exit code: $curl_exit_code"
  exit $curl_exit_code
fi

rm -f "$TMP_EXCLUSION_FILE"

print_message "[+]" "Exclusions updated" "Response from backend: $response_body"