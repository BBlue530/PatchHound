display_exclusions() {
  echo "$1" | jq -r '
    .exclusions
    | to_entries[]
    | "----------------------------------------------------------------------\n" +
      "Index            : \(.key)\n" +
      "Vulnerability ID : \(.value.vulnerability_id)\n" +
      "Scope            : \(.value.scope)\n" +
      "Public Comment   : \(.value.public_comment)\n" +
      "Private Comment : \(.value.private_comment)\n"
  '
  echo "----------------------------------------------------------------------"
}