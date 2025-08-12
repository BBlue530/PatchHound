print_message "[~]" "Generating SBOM for: $TARGET" ""
syft "$TARGET" -o cyclonedx-json > sbom.cyclonedx.json

if [ ! -f "sbom.cyclonedx.json" ]; then
  print_message "[!]" "SBOM not found" "sbom.cyclonedx.json not found"
  exit 3
fi

print_message "[+]" "SBOM created" ""