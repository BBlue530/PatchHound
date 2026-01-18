display_exclusions() {
  echo "$1" | jq -r '
    .exclusions
    | to_entries[]
    | "----------------------------------------------------------------------\n" +
      "Index            : \(.key)\n" +
      "Vulnerability ID : \(.value.vulnerability)\n" +
      "Scope            : \(.value.scope)\n" +
      "Public Comment   : \(.value.public_comment)\n" +
      "Internal Comment : \(.value.internal_comment)\n"
  '
  echo "----------------------------------------------------------------------"
}