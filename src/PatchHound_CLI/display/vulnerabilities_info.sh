print_critical_vulns() {
if [ "$CRITICAL_COUNT_SAST" -gt 0 ]; then
  echo "[!] SAST issues found:"
  jq --slurpfile exclusions exclusions.json -r '
    (.results // [])[]
    | select(.check_id as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "Rule: \(.check_id)
Severity: \(.extra.severity)
Message: \(.extra.message)
Location: \(.path):\(.start.line)
----------------------------------------------------------------------"
  ' ${PATCHHOUND_SCAN_DATA}sast_report.json
fi

if [ "$CRIT_COUNT_GRYPE" -gt 0 ]; then
echo "[!] Critical Vulnerabilities Found by Grype"
jq --slurpfile exclusions exclusions.json -r '
  (.vulnerabilities // [])[]
  | select((.ratings // [] | map(.severity // "") | map(ascii_downcase) | index("critical")) != null)
  | select(.id as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
  | .id as $ID
  | (.description // "No description available") as $DESC
  | (
      .references[0]?.url
      // (
        if ($ID | test("^GHSA")) then
          "https://github.com/advisories/" + $ID
        elif ($ID | test("^CVE")) then
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + $ID
        else
          "No link available"
        end
      )
    ) as $LINK
  | (
      (.affects[0]?.ref | capture("pkg:(?<type>[^/]+)/(?<name>[^@]+)@(?<version>.+)") 
      // {type: "unknown", name: "unknown", version: "unknown"})
    ) as $PKG
  | "ID: \($ID)
Severity: Critical
Package: \($PKG.name)@\($PKG.version)
Cause: \($DESC)
Link: \($LINK)
----------------------------------------------------------------------"
' ${PATCHHOUND_SCAN_DATA}vulns.cyclonedx.json
fi

if [ "$CRIT_COUNT_TRIVY" -gt 0 ]; then
  echo "[!] Critical Vulnerabilities Found by Trivy"
  jq --slurpfile exclusions exclusions.json -r '
    .Results[]?.Vulnerabilities[]?
    | select(.Severity == "CRITICAL")
    | select(.VulnerabilityID as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "ID: \(.VulnerabilityID)
Severity: Critical
Package: \(.PkgName)@\(.InstalledVersion)
Cause: \(.Title // .Description // "No description available")
Link: \(.PrimaryURL // "No link available")
----------------------------------------------------------------------"
  ' ${PATCHHOUND_SCAN_DATA}trivy_report.json
fi
}

print_high_vulns() {
if [ "$HIGH_COUNT_GRYPE" -gt 0 ]; then
  echo "[!] High Vulnerabilities Found by Grype"
  jq --slurpfile exclusions exclusions.json -r '
    (.vulnerabilities // [])[]
    | select((.ratings // [] | map(.severity // "") | map(ascii_downcase) | index("high")) != null)
    | select(.id as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | .id as $ID
    | (.description // "No description available") as $DESC
    | (
        .references[0]?.url
        // (
          if ($ID | test("^GHSA")) then
            "https://github.com/advisories/" + $ID
          elif ($ID | test("^CVE")) then
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + $ID
          else
            "No link available"
          end
        )
      ) as $LINK
    | (
        (.affects[0]?.ref | capture("pkg:(?<type>[^/]+)/(?<name>[^@]+)@(?<version>.+)") 
        // {type: "unknown", name: "unknown", version: "unknown"})
      ) as $PKG
    | "ID: \($ID)
Severity: High
Package: \($PKG.name)@\($PKG.version)
Cause: \($DESC)
Link: \($LINK)
----------------------------------------------------------------------"
  ' ${PATCHHOUND_SCAN_DATA}vulns.cyclonedx.json
fi

if [ "$HIGH_COUNT_TRIVY" -gt 0 ]; then
  echo "[!] High Vulnerabilities Found by Trivy"
  jq --slurpfile exclusions exclusions.json -r '
    .Results[]?.Vulnerabilities[]?
    | select(.Severity == "HIGH")
    | select(.VulnerabilityID as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "ID: \(.VulnerabilityID)
Severity: High
Package: \(.PkgName)@\(.InstalledVersion)
Cause: \(.Title // .Description // "No description available")
Link: \(.PrimaryURL // "No link available")
----------------------------------------------------------------------"
  ' ${PATCHHOUND_SCAN_DATA}trivy_report.json
fi
}

print_medium_vulns() {
if [ "$MED_COUNT_GRYPE" -gt 0 ]; then
  echo "[!] Medium Vulnerabilities Found by Grype"
  jq --slurpfile exclusions exclusions.json -r '
    (.vulnerabilities // [])[]
    | select((.ratings // [] | map(.severity // "") | map(ascii_downcase) | index("medium")) != null)
    | select(.id as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "ID: \(.id)
Severity: Medium
Description: \(.description // "No description available")
----------------------------------------------------------------------"
  ' ${PATCHHOUND_SCAN_DATA}vulns.cyclonedx.json
fi

if [ "$MED_COUNT_TRIVY" -gt 0 ]; then
  echo "[!] Medium Vulnerabilities Found by Trivy"
  jq --slurpfile exclusions exclusions.json -r '
    .Results[]?.Vulnerabilities[]?
    | select(.Severity == "MEDIUM")
    | select(.VulnerabilityID as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "ID: \(.VulnerabilityID)
Severity: Medium
Package: \(.PkgName)@\(.InstalledVersion)
Cause: \(.Title // .Description // "No description available")
Link: \(.PrimaryURL // "No link available")
----------------------------------------------------------------------"
  ' ${PATCHHOUND_SCAN_DATA}trivy_report.json
fi
}

print_low_vulns() {
if [ "$LOW_COUNT_GRYPE" -gt 0 ]; then
  echo "[!] Low Vulnerabilities Found by Grype"
  jq --slurpfile exclusions exclusions.json -r '
    (.vulnerabilities // [])[]
    | select((.ratings // [] | map(.severity // "") | map(ascii_downcase) | index("low")) != null)
    | select(.id as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "ID: \(.id)
Severity: Low
Description: \(.description // "No description available")
----------------------------------------------------------------------"
  ' ${PATCHHOUND_SCAN_DATA}vulns.cyclonedx.json
fi

if [ "$LOW_COUNT_TRIVY" -gt 0 ]; then
  echo "[!] Low Vulnerabilities Found by Trivy"
  jq --slurpfile exclusions exclusions.json -r '
    .Results[]?.Vulnerabilities[]?
    | select(.Severity == "LOW")
    | select(.VulnerabilityID as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "ID: \(.VulnerabilityID)
Severity: Low
Package: \(.PkgName)@\(.InstalledVersion)
Cause: \(.Title // .Description // "No description available")
Link: \(.PrimaryURL // "No link available")
----------------------------------------------------------------------"
  ' ${PATCHHOUND_SCAN_DATA}trivy_report.json
fi
}

print_unkown_vulns() {
if [ "$UNKNOWN_COUNT_GRYPE" -gt 0 ]; then
  echo "[!] Unknown Vulnerabilities Found by Grype"
  jq --slurpfile exclusions exclusions.json -r '
    (.vulnerabilities // [])[]
    | select((.ratings // [] | map(.severity // "") | map(ascii_downcase) | index("unknown")) != null)
    | select(.id as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "ID: \(.id)
Severity: Unknown
Description: \(.description // "No description available")
----------------------------------------------------------------------"
  ' ${PATCHHOUND_SCAN_DATA}vulns.cyclonedx.json
fi

if [ "$UNKNOWN_COUNT_TRIVY" -gt 0 ]; then
  echo "[!] Unknown Vulnerabilities Found by Trivy"
  jq --slurpfile exclusions exclusions.json -r '
    .Results[]?.Vulnerabilities[]?
    | select(.Severity == "UNKNOWN")
    | select(.VulnerabilityID as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "ID: \(.VulnerabilityID)
Severity: Unknown
Package: \(.PkgName)@\(.InstalledVersion)
Cause: \(.Title // .Description // "No description available")
Link: \(.PrimaryURL // "No link available")
----------------------------------------------------------------------"
  ' ${PATCHHOUND_SCAN_DATA}trivy_report.json
fi
}

print_cvss_vulns() {
  local threshold="$1"

  if [ "$CVSS_COUNT_GRYPE" -gt 0 ]; then
    echo "[!] Vulnerabilities in Grype with CVSS >= $threshold"
    jq --slurpfile exclusions exclusions.json --argjson threshold "$threshold" -r '
      (.vulnerabilities // [])[]
      | (.ratings[]?.score? // 0) as $score
      | select($score >= $threshold)
      | select(.id as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
      | "ID: \(.id)
CVSS Score: \($score)
Severity: \(.ratings[0]?.severity // "unknown")
Description: \(.description // "No description available")
----------------------------------------------------------------------"
    ' ${PATCHHOUND_SCAN_DATA}vulns.cyclonedx.json
  fi

  if [ "$CVSS_COUNT_TRIVY" -gt 0 ]; then
    echo "[!] Vulnerabilities in Trivy with CVSS >= $threshold"
    jq --slurpfile exclusions exclusions.json --argjson threshold "$threshold" -r '
      .Results[]?.Vulnerabilities[]?
      | (.CVSS.nvd?.V3Score // .CVSS.nvd?.V2Score // .CVSS.redhat?.Score // 0) as $score
      | select($score >= $threshold)
      | select(.VulnerabilityID as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
      | "ID: \(.VulnerabilityID)
CVSS Score: \($score)
Severity: \(.Severity)
Package: \(.PkgName)@\(.InstalledVersion)
Cause: \(.Title // .Description // "No description available")
Link: \(.PrimaryURL // "No link available")
----------------------------------------------------------------------"
    ' ${PATCHHOUND_SCAN_DATA}trivy_report.json
  fi
}

print_trivy_misconf_secrets() {
if [ "$MISCONF_COUNT_TRIVY" -gt 0 ]; then
  echo
  echo "[!] Misconfigurations Found by Trivy"
  jq --slurpfile exclusions exclusions.json -r '
    .Results[]?.Misconfigurations[]?
    | select(.ID as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "ID: \(.ID)
Severity: \(.Severity)
File: \(.Target)
Check: \(.Title // .Description // "No description")
Resolution: \(.Resolution // "No fix guidance")
Link: \(.PrimaryURL // .References[0] // "No link available")
----------------------------------------------------------------------"
  ' ${PATCHHOUND_SCAN_DATA}trivy_report.json
fi

if [ "$SECRET_COUNT_TRIVY" -gt 0 ]; then
  echo
  echo "[!] Secrets Found by Trivy"
  jq --slurpfile exclusions exclusions.json -r '
    .Results[]?.Secrets[]?
    | select(.RuleID as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "Rule ID: \(.RuleID)
File: \(.Target)
Severity: \(.Severity)
Title: \(.Title // "No title")
----------------------------------------------------------------------"
  ' ${PATCHHOUND_SCAN_DATA}trivy_report.json
fi
}