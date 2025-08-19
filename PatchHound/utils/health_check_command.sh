TOKEN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)
            TOKEN="$2"
            shift 2
            ;;
        *)
    esac
done

if [ -z "$TOKEN" ]; then
    print_message "[!]" "Missing flag" "--token is required"
fi

health_response=$(curl -sSL "$HEALTH_CHECK_API_URL" \
        -G \
        --data-urlencode "token=$TOKEN")
if ! echo "$health_response" | grep -q '"status":"ok"'; then
  print_message "[!]" "Backend health" "Backend health check failed
  $health_response"
  exit 1
else
  print_message "[i]" "Backend health" "Backend health check succeeded
  $health_response"
fi