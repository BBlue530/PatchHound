# PatchHound (SBOM Vulnerability Report Generator)

An open-source, plug-and-play **SBOM (Software Bill of Materials) vulnerability scanner** that generates comprehensive vulnerability reports for container images or source code repositories.

---

## Features

- Automatically generates an SBOM using [Syft](https://github.com/anchore/syft)
- Scans for vulnerabilities with [Grype](https://github.com/anchore/grype)
- Includes [trivy](https://github.com/aquasecurity/trivy) to complement Syft + Grype with misconfigurations and secrets detection
- Signs attestation with [Cosign](https://github.com/sigstore/cosign)
- Compare found vulnerabilities with [KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Runs Static Application Security Testing (SAST) with [Semgrep](https://github.com/semgrep/semgrep), catching code vulnerabilities and security issues directly in your source code
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
- CLI for interacting with the backend

---

## Usage

# Backend

The backend handles file ingestion, vulnerability scanning, prioritization, and storage.
It receives SBOMs, SAST reports, and Trivy results from the CLI or CI/CD pipelines, processes them, signs results, compares vulnerabilities against the CISA KEV catalog, and triggers alerts when needed.

For installation, setup, and detailed API documentation, see the [Backend README](https://github.com/BBlue530/PatchHound_Advanced/tree/master/Backend/README.md).

# CLI
The CLI is a core part of the communication between the backend and user. Read more on how to use the CLI [here](https://github.com/BBlue530/PatchHound_Advanced/tree/master/PatchHound/README.md).

## What you can expect:
```
===============================================
          PatchHound - by BBlue530
===============================================
[~] Generating Summary
[i] Vulnerability assessment:
---------------------------------------------------------------------------
[+] Grype Results:
Critical: 18
High: 38
Medium: 28
Low: 3
Unknown: 0
---------------------------------------------------------------------------
[+] Trivy Results:
Critical: 18
High: 38
Medium: 28
Low: 3
Unknown: 0
Misconfigurations: 0
Exposed Secrets: 0
---------------------------------------------------------------------------
[+] SAST Results:
Critical: 1
Issues: 2
---------------------------------------------------------------------------
```

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
[Semgrep] → Vulnerability report
[Trivy] → Vulnerability, misconfig, exposed secrets report

   ↓

[cURL] → Send payload to Backend API:
   - Form data:
     - SBOM file (CycloneDX JSON)
     - Semgrep SAST report
     - Trivy report
     - token key

   ↓

[Backend / Flask API]
   ├─ Validate token key
   ├─ Validate SBOM JSON format
   ├─ Run Grype scan on SBOM
   ├─ Compare vulnerabilities with KEV catalog
   ├─ Start async thread to save scan data:
   │    ├─ Save alert webhook config under:
   │    │    organization/repo_name/{repo_name}_alert.json
   │    ├─ Generate Cosign key-pair under:
   │    │    organization/repo_name/timestamp/{repo_name}.key & .pub
   │    ├─ Save SBOM, SAST report, Trivy report, vulnerabilities, prioritized KEV matches to:
   │    │    organization/repo_name/timestamp/
   │    │        ├─ {repo_name}_sbom_cyclonedx.json
   │    │        ├─ {repo_name}_sast_report.json
   │    │        ├─ {repo_name}_vulns_cyclonedx.json
   │    │        ├─ {repo_name}_prio_vuln_data.json
   │    │        ├─ Cosign attestation & signature files
   │    ├─ Check vulnerabilities, misconfigurations, exposed secrets and trigger alert if needed
   │    └─ Log all events to:
   │         organization/repo_name/{repo_name}_event_log.json
   └─ Return JSON response with vulnerability scan, KEV prioritization and jwt for accessing the stored resources.
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
   ├─ If reachable:
   │    ├─ Remove old KEV catalog JSON file
   │    ├─ Download and save new KEV catalog JSON
   │    └─ Log success
   └─ If unreachable or error:
        ├─ Log warning/error but continue

   ↓

[Run SBOM Validation & Rescanning]
   ├─ Iterate over all organizations and repos under the `all_repo_scans_folder`
   ├─ For each repo:
   │    ├─ Find latest timestamp folder
   │    ├─ Verify existence of SBOM, Attestation, and Signature files
   │    ├─ Verify SBOM attestation and signature using Cosign
   │    ├─ If any verification fails:
   │    │    ├─ Trigger alert
   │    │    └─ Log event with timestamp
   │    ├─ If verified:
   │    │    ├─ Run Grype scan on SBOM
   │    │    ├─ Load previous vulnerability report
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