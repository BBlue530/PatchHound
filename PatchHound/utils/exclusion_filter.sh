exclusions_filter() {
  local file="$1"
  local jq_filter="$2"
  local id_field="$3"

  jq --slurpfile exclusions exclusions.json "
    [$jq_filter
     | select(.$id_field as \$vid
         | (\$exclusions[0].exclusions | map(.vulnerability) | index(\$vid)) | not)
    ] | length" "$file"
}