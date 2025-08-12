health_response=$(curl -s "$HEALTH_CHECK_API_URL")
if ! echo "$health_response" | grep -q '"status":"ok"'; then
  print_message "[!]" "Backend health" "Backend health check failed
  $health_response"
  exit 1
fi