print_message() {
  local prefix="$1"
  local title="$2"
  local description="$3"
  local width=${4:-70}

  local RESET=$'\e[0m'
  local BOLD=$'\e[1m'

  printf "%b %b%b%b\n" "$prefix" "$BOLD" "$title" "$RESET"
  if [[ -n "$description" ]]; then
    echo "$description" | fold -s -w "$width"
  fi
}
