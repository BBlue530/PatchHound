print_message "[~]" "Signing image with sign service..." ""

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    print_message "[~]" "Image not found locally, pulling $IMAGE..."
    docker pull "$IMAGE"
fi

IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE")

response_and_status=$(curl --connect-timeout 60 --max-time 300 -s -w "\n%{http_code}" \
  -F "token=$TOKEN" \
  -F "image_digest=$IMAGE_DIGEST" \
  -F "image_name=$IMAGE" \
  "$BASE_IMAGE_SIGN_API_URL")

curl_exit_code=$?
http_status=$(echo "$response_and_status" | tail -n1)
response_body=$(echo "$response_and_status" | head -n -1)

if [[ "$http_status" -ne 200 ]]; then
  message=$(echo "$response_body" | jq -r '.message')
  print_message "[!]" "Backend error" "Status Code: $http_status
  $message"
  exit 1
fi

if [ $curl_exit_code -ne 0 ]; then
  print_message "[!]" "Backend error" "Curl failed with exit code: $curl_exit_code"
  exit $curl_exit_code
fi

print_message "[+]" "Signing finished" "Signing of image with backend finished successfully"