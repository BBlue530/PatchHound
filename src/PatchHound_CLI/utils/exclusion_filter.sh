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

find_exclusions_file() {
    local dir="${1:-$PWD}"
    while [[ "$dir" != "/" ]]; do
        if [[ -f "$dir/exclusions.json" ]]; then
            echo "$dir/exclusions.json"
            return
        fi
        dir=$(dirname "$dir")
    done
    return 1
}

exclusions_filter_semgrep() {
  local file="$1"
  local jq_filter="$2"

  jq --slurpfile exclusions exclusions.json "
    [
      $jq_filter
      | (
          \"semgrep_\" + .check_id + \"_\" +
          (.extra.fingerprint // \"unknown_fingerprint\")
        ) as \$vid
      | select(
          (\$exclusions[0].exclusions | map(.vulnerability) | index(\$vid)) | not
        )
    ]
    | length
  " "$file"
}