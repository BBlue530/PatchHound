health_response=$(curl -s "$HEALTH_CHECK_API_URL")
if ! echo "$health_response" | grep -q '"status":"ok"'; then
  echo "[!] Backend health check failed:"
  echo "$health_response"
  exit 1
fi