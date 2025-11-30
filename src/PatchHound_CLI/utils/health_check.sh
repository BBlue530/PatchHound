if [ -z "$TOKEN" ]; then
    print_message "[!]" "Missing flag" "--token is required"
fi

health_response=$(curl -sSL "$HEALTH_CHECK_API_URL" \
        -G \
        --data-urlencode "token=$TOKEN")
if ! echo "$health_response" | grep -iqE '"status"\s*:\s*"ok"'; then
  print_message "[!]" "Backend health" "Backend health check failed
  $health_response"
  exit 1
else
  print_message "[i]" "Backend health" "Backend health check succeeded
  $health_response"
fi