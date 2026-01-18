source "$BASE_DIR/exclusion_handling/exclusion_display.sh"
source "$BASE_DIR/exclusion_handling/exclusion_add_entry.sh"
source "$BASE_DIR/exclusion_handling/exclusion_delete_entry.sh"

edit_exclusions() {
while true; do
  
  echo "Select entry to edit(index)"
  echo "Add a new entry(A)"
  echo "Remove entry(D)"
  echo "Save changes(S)"
  echo "Quit(Q)"
  read -p "Input: " ENTRY_INDEX

  if [[ "$ENTRY_INDEX" = "S" || "$ENTRY_INDEX" = "s" ]]; then
    break
  fi

  if [[ "$ENTRY_INDEX" = "Q" || "$ENTRY_INDEX" = "q" ]]; then
    exit 0
  fi

  if [[ "$ENTRY_INDEX" = "A" || "$ENTRY_INDEX" = "a" ]]; then
    add_exclusions
    display_exclusions "$response_body"
    continue
  fi

  if [[ "$ENTRY_INDEX" = "D" || "$ENTRY_INDEX" = "d" ]]; then
    delete_exclusions
    display_exclusions "$response_body"
    continue
  fi

  ENTRY_COUNT=$(echo "$response_body" | jq '.exclusions | length')

  if ! [[ "$ENTRY_INDEX" =~ ^[0-9]+$ ]] || [ "$ENTRY_INDEX" -ge "$ENTRY_COUNT" ]; then
    print_message "[!]" "Invalid selection" "Index out of range"
    display_exclusions "$response_body"
    continue
  fi

  echo "Select field to edit:"
  echo "1) vulnerability"
  echo "2) scope"
  echo "3) public_comment"
  echo "4) internal_comment"

  read -p "Choice: " FIELD_CHOICE

  case "$FIELD_CHOICE" in
    1) FIELD="vulnerability" ;;
    2) FIELD="scope" ;;
    3) FIELD="public_comment" ;;
    4) FIELD="internal_comment" ;;
    *)
      print_message "[!]" "Invalid selection" "Unknown field"
      display_exclusions "$response_body"
      continue
      ;;
  esac

  CURRENT_VALUE=$(echo "$response_body" | jq -r ".exclusions[$ENTRY_INDEX].$FIELD")
  echo "Current value:"
  echo "$CURRENT_VALUE"

  read -p "Enter new value: " NEW_VALUE

  response_body=$(echo "$response_body" | jq \
    --arg value "$NEW_VALUE" \
    ".exclusions[$ENTRY_INDEX].$FIELD = \$value"
  )

  display_exclusions "$response_body"

done
}