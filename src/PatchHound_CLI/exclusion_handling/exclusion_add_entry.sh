add_exclusions() {
    read -p "vulnerability_id ID: " VULN_ID
    read -p "Scope: " SCOPE
    read -p "Public Comment: " PUBLIC_COMMENT
    read -p "Private Comment : " PRIVATE_COMMENT

  response_body=$(echo "$response_body" | jq \
    --arg vulnerability_id "$VULN_ID" \
    --arg scope "$SCOPE" \
    --arg public_comment "$PUBLIC_COMMENT" \
    --arg private_comment "$PRIVATE_COMMENT" \
    '.exclusions += [{
      vulnerability_id: $vulnerability_id,
      scope: $scope,
      public_comment: $public_comment,
      private_comment: $private_comment
    }]'
  )
}