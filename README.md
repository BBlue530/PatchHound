# SBOM Vulnerability Report Generator

An open-source, plug-and-play **SBOM (Software Bill of Materials) vulnerability scanner** that generates comprehensive vulnerability reports for container images or source code repositories.

---

## Features

- Automatically generates an SBOM using [Syft](https://github.com/anchore/syft)
- Scans for vulnerabilities with [Grype](https://github.com/anchore/grype)
- Signs attestation with [Cosign](https://github.com/sigstore/cosign)
- Compare found vulnerabilities with [KEV catalong](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Daily SBOM scan for new vulnerabilities, including:
   - Automatic update of the Grype vulnerability database
   - Automatic fetch of the latest KEV catalog
   - Re-scan of the latest SBOMs using updated databases
   - Automatic verification of the SBOMs attestation and signing
   - Alerts if verification fails or new vulnerabilities have been found
- Outputs detailed vulnerability counts by severity
- Lists top critical vulnerabilities found
- Alerts on [Discord](https://discord.com/) / [Slack](https://slack.com/) when vulnerabilities are found
- Configurable via a simple `scan.config` file
- Works on source repos or container images
- Supports multiple concurrent scans with worker-based processing

---

## Usage

1. Clone or add the repository containing the scanner script (`scan.sh`) and config (`scan.config`) along with (`.github`) folder into your own GitHub repository.

2. Configure the `scan.config` file:

   ```bash
   # Example config to scan a container image
   TARGET="ghcr.io/<your-name>/<your-image>"
   FAIL_ON_CRITICAL=true
   ```
   
   or to scan the current repository directory:

   ```bash
   # Example config to scan a current repository
   TARGET="."
   FAIL_ON_CRITICAL=true
   ```
3. Make sure to update the GitHub Actions workflow file (`secure-pipeline.yml`) inside `.github\workflows\secure-pipeline.yml` and change the branch.
   ```
   branches: [<your-branch-name>]
   ```
4. Make sure to update your secrets.

   `SBOM_SCAN_API_URL` is the url of your backend (**MANDATORY**). If not set the backend will not receive the SBOM.

   `ALERT_WEBHOOK` is the webhook you will get alerts. If its not set you will not receive alerts.

   `LICENSE_SECRET` is a license that will get checked on your backend to restrict access if not set properly (**MANDATORY**).

   `GHCR_PAT` is the PAT you will have to provide but is not needed if you do not plan on scanning images.

   ```
    SBOM_SCAN_API_URL: ${{ secrets.SBOM_SCAN_API_URL }}
    ALERT_WEBHOOK: ${{ secrets.ALERT_WEBHOOK }}
    LICENSE_SECRET: ${{ secrets.LICENSE_SECRET }}
    GHCR_PAT: ${{ secrets.GHCR_PAT }}
   ```
5. Start backend by being in the `Backend` directory `cd Backend` and starting the bash script `bash Start.sh`.

6. Next time you push to the repository, the GitHub Actions workflow will automatically run the scan for you.
  
7. You can check the results in the Actions > select the workflow run for your commit and then either go to the `Run SBOM Scan Script` or find the summary report inside the workflow where you can find the `vulnerability-summary` file as an artifact and can download the full report from there.

## What you can expect:
```
===============================================
          PatchHound - by BBlue530
===============================================
[~] Generating SBOM For: ghcr.io/bblue530/my-app:latest
[+] SBOM Created: sbom.json
[~] Scanning For Vulnerabilities
[+] Vulnerability Report: vulns.json
[i] Vulnerability Report:
Critical: 327
High: 761
Medium: 700
Low: 99
Unknown: 1
[~] Generating Summary
---------------------------------------------------------------------------
ID: CVE-2022-23943
Severity: Critical
Package: apache2-bin@2.4.25-3+deb9u5
Cause: Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap memory with possibly attacker provided data. This issue affects Apache HTTP Server 2.4 version 2.4.52 and prior versions.
Fix: 2.4.25-3+deb9u13
Link: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23943
---------------------------------------------------------------------------
ID: CVE-2022-2068
Severity: Critical
Package: libssl1.1@1.1.0f-3+deb9u2
Cause: In addition to the c_rehash shell command injection identified in CVE-2022-1292, further circumstances where the c_rehash script does not properly sanitise shell metacharacters to prevent command injection were found by code review. When the CVE-2022-1292 was fixed it was not discovered that there are other places in the script where the file names of certificates being hashed were possibly passed to a command executed through the shell. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.4 (Affected 3.0.0,3.0.1,3.0.2,3.0.3). Fixed in OpenSSL 1.1.1p (Affected 1.1.1-1.1.1o). Fixed in OpenSSL 1.0.2zf (Affected 1.0.2-1.0.2ze).
Fix: No fix available
Link: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2068
---------------------------------------------------------------------------
ID: CVE-2020-9490
Severity: High
Package: apache2-bin@2.4.25-3+deb9u5
Cause: Apache HTTP Server versions 2.4.20 to 2.4.43. A specially crafted value for the 'Cache-Digest' header in a HTTP/2 request would result in a crash when the server actually tries to HTTP/2 PUSH a resource afterwards. Configuring the HTTP/2 feature via "H2Push off" will mitigate this vulnerability for unpatched servers.
Fix: No fix available
Link: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9490
---------------------------------------------------------------------------
```
---

## Compatibility

Out of the box this project currently only works with **GitHub Actions** for automated scanning.

---

## Notes

When scanning a directory (`TARGET="."`), Syft will warn about missing explicit name/version metadata. This does **not** affect scan results.

If you dont want the workflow to fail when critical vulnerabilities are found change `FAIL_ON_CRITICAL=true` to `false`

If you are scanning a container image, make sure to add a secret named `GHCR_PAT` to your repository:

1. Go to **Settings > Secrets and variables > Actions**
2. Click **New repository secret**
3. Name it: `GHCR_PAT`
4. Paste your [GitHub Personal Access Token (PAT)](https://github.com/settings/tokens)

### Required Token Permissions

- **`read:packages`** - required to pull images from GitHub Container Registry (GHCR)
- **`repo`** - only required if you are accessing **private images** or **private repositories**

Public images only require `read:packages`.

---

# Workflow Diagram

This diagram outlines the detailed structure of the security scanning and vulnerability prioritization workflow. It captures both the pipeline process triggered during code commits and the daily automated cron job that maintains and validates scan data integrity.

## Pipeline Workflow

```
Pipeline Triggered

   ↓

[Syft] → Generate SBOM (CycloneDX JSON)

   ↓

[cURL] → Send payload to Backend API:
   - Form data:
     - SBOM file (CycloneDX JSON)
     - license key
     - current_repo (repo name)
     - alert_system_webhook (URL)
     - commit_sha
     - commit_author

   ↓

[Backend / Flask API]
   ├─ Validate license key (License_Handling.validate_license)
   ├─ Validate SBOM JSON format (Check_Format.check_json_format + json.load)
   ├─ Save SBOM temporarily
   ├─ Run Grype scan on SBOM (subprocess, output CycloneDX JSON)
   ├─ Compare vulnerabilities with KEV catalog (Kev_Catalog.compare_kev_catalog)
   ├─ Start async thread to save scan data (File_Save.save_scan_files):
   │    ├─ Save alert webhook config under:
   │    │    license_key/repo_name/{repo_name}_alert.json
   │    ├─ Generate Cosign key-pair if missing under:
   │    │    license_key/repo_name/timestamp/{repo_name}.key & .pub
   │    ├─ Save SBOM, vulnerabilities, prioritized KEV matches to:
   │    │    license_key/repo_name/timestamp/
   │    │        ├─ {repo_name}_sbom_cyclonedx.json
   │    │        ├─ {repo_name}_vulns_cyclonedx.json
   │    │        ├─ {repo_name}_prio_vuln_data.json
   │    │        ├─ Cosign attestation & signature files
   │    ├─ Check vulnerabilities and trigger alert if needed (Vuln_Check.check_vuln_file)
   │    └─ Log all events to:
   │         license_key/repo_name/{repo_name}_event_log.json
   └─ Return JSON response with vulnerability scan and KEV prioritization
```
## Daily Cron Job Workflow

```
Cron Trigger: scheduled_event()

   ↓

[Update Grype DB]
   ├─ Backup existing Grype DB cache (~/.cache/grype → ~/.cache/grype_backup)
   ├─ Run "grype db update"
   ├─ On success:
   │    ├─ Remove backup cache
   └─ On failure:
        ├─ Restore backup cache (if available)
        └─ Log error message

   ↓

[Update KEV Catalog]
   ├─ Send HEAD request to KEV Catalog URL
   ├─ If reachable (HTTP 200):
   │    ├─ Remove old KEV catalog JSON file (if exists)
   │    ├─ Download and save new KEV catalog JSON
   │    └─ Log success
   └─ If unreachable or error:
        ├─ Log warning/error but continue

   ↓

[Run SBOM Validation & Rescanning]
   ├─ Iterate over all license keys and repos under the `all_repo_scans_folder`
   ├─ For each repo:
   │    ├─ Find latest timestamp folder
   │    ├─ Verify existence of SBOM, Attestation, and Signature files
   │    ├─ Verify SBOM attestation and signature using Cosign
   │    ├─ If any verification fails:
   │    │    ├─ Trigger alert (with repo alert webhook config)
   │    │    └─ Log event with commit info and timestamp
   │    ├─ If verified:
   │    │    ├─ Run Grype scan on SBOM (CycloneDX JSON output)
   │    │    ├─ Load previous vulnerability report (if exists)
   │    │    ├─ Compare current vulnerabilities with previous scan
   │    │    │    ├─ Identify new vulnerabilities
   │    │    │    ├─ If new vulnerabilities found:
   │    │    │    │    ├─ Trigger alert (with details of new vulns)
   │    │    │    └─ Else: continue silently
   │    │    ├─ Save vulnerabilities report JSON (overwrite previous)
   │    │    ├─ Compare vulnerabilities to KEV catalog, save priority report JSON
   │    │    └─ Log scan success
   │    └─ If scan fails:
   │         ├─ Trigger alert
   │         └─ Log failure event
```
## Deployment

```
[Deployment / Runtime]

└─ Start.sh (Bash script):
     ├─ Create Python virtual environment if missing
     ├─ Install dependencies from requirements.txt
     └─ Launch Gunicorn:
         - 2 workers × 4 threads
         - Preloaded app (Main:app)

↓
[Gunicorn WSGI Server]
   ├─ Worker 1 (4 threads)
   └─ Worker 2 (4 threads)
```

---

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

---

⚠️ **Warning:** Run this workflow on only one main branch to keep runs minimal and avoid GitHub Actions rate limits.

---