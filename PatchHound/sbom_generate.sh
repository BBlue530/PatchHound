echo "[~] Generating SBOM for: $TARGET"
syft "$TARGET" -o cyclonedx-json > sbom.cyclonedx.json

if [ ! -f "sbom.cyclonedx.json" ]; then
  echo "[!] Error: sbom.cyclonedx.json not found"
  exit 3
fi

echo "[+] SBOM created"