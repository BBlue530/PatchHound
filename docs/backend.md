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
- Generate JSON and PDF summary reports for workflows
- Manage exclusions of vulnerabilities across versions
- Supports 3rd party secret managers
- Repository history tracking
- Audit trail

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

If `secrets.json` with valid secrets are missing the backend will generate valid values which will include an api key which you will need to `change` and `create` token keys.
Example:
```
======================================
[!] NEW API KEY GENERATED:
UmA-amMq-FaMnF_aFNegzQ5hozYjOffwy8yJVgIeV18
======================================
```

This single command will:
- Install all required scanning tools and dependencies automatically
- Initialize the database to store token keys and related data (if it doesn't already exist)
- Start the daily vulnerability scan scheduler to keep everything continuously monitored
- Verify secret values exist and generate them if needed
Once running the backend will be managing updates, scans and alerts. 

### Secret Manager

By default PatchHound will generate secrets for you if no external secret manager is configured. 

In the root of the Backend you can find `config.py` where you can customize the backend settings and switch from the default local secret storage to a third party secret manager. 

Currently AWS Secrets Manager is supported and there are plans to add support for additional secret managers in the future. 

If you want to use a secret manager that is not supported you can enable `CUSTOM_SECRETS` in `config.py` and implement your own logic in `custom_secret_manager.py`. You will have to provide the code that retrieves secrets for `api_key`, `jwt_key` and `cosign_key` and PatchHound will call your function automatically. 

Currently PatchHound is expecting these secrets:
- `api_key`
- `jwt_key`
- `cosign_key`

---

## File System

PatchHound organizes all scan results and resources in a token based file system.
When you run a scan, the backend issues a token JWT that acts as a key to retrieve the full set of files and reports generated for that run.

- **Token based access:** The issued token allows you to securely fetch all artifacts for a given workflow run.

- **Exclusion aware summaries:** PatchHound generates a comprehensive summary report with all vulnerabilties that has been found and automatically respects your configured exclusions and includes any comments and justifications you have for the exclusions.

- **Repository history:** Every scan is preserved enabling PatchHound to produce a full historical report of vulnerabilities over time.

---

## Audit track

Throughout the entire PatchHound workflow every significant action is tracked and recorded in a structured audit log. This includes:

- SBOM, attestation and signature
- Vulnerability scans
- KEV catalog checks and prioritized vulnerabilities
- Signature and attestation verification
- Alerts triggered

Each audit log entry includes a timestamp, action type, relevant details and any alerts generated. 

Once the audit log is complete a SHA-256 hash of the log is stored. This hash is linked to the repositorys history file providing a tamper evident record of the workflow run and enabling traceability for compliance audits. 

---

## Workflow Diagram

This diagram outlines the detailed structure of the security scanning and vulnerability prioritization workflow. It captures both the pipeline process triggered during code commits and the daily automated cron job that maintains and validates scan data integrity.

### Pipeline Workflow

```
CLI Scan

   ↓

[Syft] → SBOM (CycloneDX JSON)
[Semgrep] → SAST report
[Trivy] → Vulns, misconfigs, secrets

   ↓

[Backend API]
   ├─ Validate token & input
   ├─ Run Grype scan on SBOM
   ├─ Compare vulns with KEV catalog
   ├─ Respect exclusions.json
   │    └─ Excluded issues wont trigger alerts
   │       (but are still recorded in reports)
   ├─ Generate summary report
   │    └─ Includes all results + exclusion justifications
   │       (exportable to JSON/PDF)
   ├─ Save reports + Cosign signatures
   ├─ Trigger alerts if non excluded issues found
   └─ Return JSON response (scan results + KEV prioritization)
```
### Daily Cron Job Workflow

```
Cron Trigger: scheduled_event()

   ↓

[Update Databases]
   ├─ Refresh Grype vuln DB
   └─ Refresh KEV catalog

   ↓

[Re scan Stored Repos]
   ├─ Verify SBOM signatures (Cosign)
   ├─ Run Grype scan on SBOM
   ├─ Compare with previous results
   ├─ Trigger alerts if new vulns found
   └─ Save updated reports + logs
```

---