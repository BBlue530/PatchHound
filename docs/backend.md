# Backend PatchHound

---

## Overview

PatchHound Backend is the heart of the system. It handles ingesting SBOMs, scanning for vulnerabilities, managing alerts, and generating reports. It also supports signing and verifying container images as part of workflows ensuring that your software supply chain stays secure and verifiable.

---

## Features

- Ingest and store SBOMs and vulnerability reports
- Attest SBOMs and sign the attestation
- Sign and verify container images in workflows
- Send alerts using webhooks
- Log all backend events
- Automatically update vulnerability databases and rescan for new issues
- Handle multiple requests simultaneously
- Generate JSON and PDF summary reports for workflows
- Manage exclusions of vulnerabilities across versions

---

## Getting Started

### Starting the Backend  

Getting started with PatchHounds backend you have to move into the `Backend` directory.
```
cd Backend
```

Then start the backend:
```bash
bash Start.sh
```

This single command will:
- Install all required scanning tools and dependencies automatically
- Initialize the database to store token keys and related data (if it doesn't already exist)
- Start the daily vulnerability scan scheduler to keep everything continuously monitored
Once running the backend will be managing updates, scans and alerts.

---

# Workflow Diagram

This diagram outlines the detailed structure of the security scanning and vulnerability prioritization workflow. It captures both the pipeline process triggered during code commits and the daily automated cron job that maintains and validates scan data integrity.

## Pipeline Workflow

```
CLI Scan

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
   │    │        ├─ {repo_name}_summary_report.json
   │    │        ├─ {repo_name}_exclusions_file.json
   │    │        ├─ Cosign attestation & signature files
   │    ├─ Check vulnerabilities, misconfigurations, exposed secrets and trigger alert if needed (excludes all vulnerabilities inside of exclusions.json)
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
   │    │    │    ├─ Identify new vulnerabilities (excludes all vulnerabilities inside of exclusions.json)
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