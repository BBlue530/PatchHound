print_message "[~]" "Generating SBOM for: $TARGET" ""
"$BASE_DIR_BIN/syft" "$TARGET" -o cyclonedx-json > ${PATCHHOUND_SCAN_DATA}sbom.cyclonedx.json

if [ ! -f "${PATCHHOUND_SCAN_DATA}sbom.cyclonedx.json" ]; then
  print_message "[!]" "SBOM not found" "sbom.cyclonedx.json not found"
  exit 3
fi

print_message "[+]" "SBOM created" ""