FAIL="false"
PATH_TO_RESOURCES_TOKEN_BASE64=$(printf "%s" "$PATH_TO_RESOURCES_TOKEN" | base64)

echo "$PATH_TO_RESOURCES_TOKEN_BASE64" > path_to_resources_token.txt
echo "[+] Path Token to access resources sent to backend: $PATH_TO_RESOURCES_TOKEN_BASE64"

if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$CRIT_COUNT_GRYPE" -gt 0 ]; then
  echo "[!] Failing due to $CRIT_COUNT_GRYPE critical vulnerabilities found by Grype scan."
  FAIL="true"
fi

if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$CRITICAL_COUNT_SAST" -gt 0 ]; then
  echo "[!] Failing due to $CRITICAL_COUNT_SAST critical issues found by SAST scan."
  FAIL="true"
fi

if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$CRIT_COUNT_TRIVY" -gt 0 ]; then
  echo "[!] Failing due $CRIT_COUNT_TRIVY critical vulnerabilities found by Trivy scan."
  FAIL="true"
fi

if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$MISCONF_COUNT_TRIVY" -gt 0 ]; then
  echo "[!] Failing due $MISCONF_COUNT_TRIVY misconfigurations found by Trivy scan."
  FAIL="true"
fi

if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$SECRET_COUNT_TRIVY" -gt 0 ]; then
  echo "[!] Failing due $SECRET_COUNT_TRIVY secrets found by Trivy scan."
  FAIL="true"
fi

if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$FAIL" = "true" ]; then
  exit 1
fi