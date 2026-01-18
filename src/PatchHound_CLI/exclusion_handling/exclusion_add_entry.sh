add_exclusions() {
    read -p "Vulnerability ID: " VULN_ID
    read -p "Scope: " SCOPE
    read -p "Public Comment: " PUBLIC_COMMENT
    read -p "Internal Comment : " INTERNAL_COMMENT

  response_body=$(echo "$response_body" | jq \
    --arg vulnerability "$VULN_ID" \
    --arg scope "$SCOPE" \
    --arg public_comment "$PUBLIC_COMMENT" \
    --arg internal_comment "$INTERNAL_COMMENT" \
    '.exclusions += [{
      vulnerability: $vulnerability,
      scope: $scope,
      public_comment: $public_comment,
      internal_comment: $internal_comment
    }]'
  )
}