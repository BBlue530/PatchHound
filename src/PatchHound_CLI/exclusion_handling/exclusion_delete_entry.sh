delete_exclusions() {
  read -p "Select entry to remove (index): " ENTRY_INDEX

  ENTRY_COUNT=$(echo "$response_body" | jq '.exclusions | length')

  if ! [[ "$ENTRY_INDEX" =~ ^[0-9]+$ ]] || [ "$ENTRY_INDEX" -ge "$ENTRY_COUNT" ]; then
    print_message "[!]" "Invalid selection" "Index out of range"
    display_exclusions "$response_body"
    return
  fi

  echo "Entry to be removed:"
  echo "$response_body" | jq -r ".exclusions[$ENTRY_INDEX]"

  read -p "Remove entry? (y/n): " CONFIRM
  [[ "$CONFIRM" != "y" ]] && return

  response_body=$(echo "$response_body" | jq \
    "del(.exclusions[$ENTRY_INDEX])"
  )

  print_message "[i]" "Entry removed" "Index $ENTRY_INDEX deleted"
}