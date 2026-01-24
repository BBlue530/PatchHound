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
- Log exporter using opentelemetry
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

## Summary report

For every PatchHound scan the backend generates a comprehensive summary report that provides the results of the scan without the excessive noise produced by traditional scanners. Detailed output from the scanners is always available alongside the summary report for deeper inspection.

Each summary report is hashed and stored in the repositorys history under the timestamp when the scan was executed. This provides a way to confirm that the report has not been modified or tampered with after generation.

**Example summary report:**
```
{
    "repo_name": "test-repo",
    "packages": [
        {
            "source": "syft",
            "id": "pkg:pypi/apscheduler@3.10.1?package-id=f59e2e139c56ad1e",
            "name": "apscheduler",
            "version": "3.10.1",
            "type": "library",
            "purl": "pkg:pypi/apscheduler@3.10.1",
            "cpe": "cpe:2.3:a:python-apscheduler:python-apscheduler:3.10.1:*:*:*:*:*:*:*",
            "package_type": "python",
            "language": "python",
            "metadata_type": "python-pip-requirements-entry",
            "found_by": "python-package-cataloger",
            "locations": [
                "/Backend/requirements.txt"
            ]
        }
    ],
    "vulnerabilities": [
        {
            "source": "grype",
            "id": "GHSA-w853-jp5j-5j7f",
            "type": "vulnerability",
            "description": "filelock has a TOCTOU race condition which allows symlink attacks during lock file creation",
            "severity": "medium",
            "score": 6.3,
            "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H",
            "package": "filelock",
            "version": "3.18.0?package-id=pkg%3Apypi%2Ffilelock%403.18.0%3Fpackage-id%3D06e0056fd56eb9f2",
            "link": "https://github.com/advisories/GHSA-w853-jp5j-5j7f"
        },
        {
            "source": "semgrep",
            "id": "semgrep_python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host_c34c54571de9f1b58db19628a7279a14178fe308d540ade3ac8eab1ae1c9ef6b153c3441293a19cbbbe61ec19e37f33cbdfa7088d304dbdfaa5ed0dc7d15cc6b_0",
            "type": "vulnerability",
            "description": "Running flask app with host 0.0.0.0 could expose the server publicly.",
            "severity": "WARNING",
            "path": "Backend/app.py",
            "line": 37
        },
        {
            "source": "trivy_vulnerability",
            "id": "CVE-2025-68146",
            "type": "vuln",
            "description": "filelock: filelock: Time-of-Check-Time-of-Use (TOCTOU) race condition and symlink attack allows arbitrary file corruption or truncation",
            "severity": "MEDIUM",
            "score": 6.3,
            "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H",
            "package": "filelock",
            "version": "3.18.0",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2025-68146"
        },
        {
            "source": "trivy_secret",
            "id": "aws-secret-access-key",
            "type": "secret",
            "description": "No description available",
            "severity": "CRITICAL",
            "title": "AWS Secret Access Key",
            "file": null,
            "message": null
        }
    ],
    "kev_vulnerabilities": [],
    "exclusions": [
        {
            "source": "trivy_misconfiguration",
            "id": "DS002",
            "type": "misconfiguration",
            "description": "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
            "severity": "HIGH",
            "links": [
                "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
                "https://avd.aquasec.com/misconfig/ds002"
            ],
            "title": "Image user should not be 'root'",
            "resolution": "Add 'USER <non root user name>' line to the Dockerfile",
            "file": null,
            "scope": "Dockerfile",
            "public_comment": "Container runs as root in isolated test VM no exposure to untrusted networks or sensitive data.",
            "internal_comment": "High-severity in production, but acceptable in controlled test environment. Must be fixed before deployment."
        }
    ],
    "counters": {
        "package_counter": 9,
        "kev_vuln_counter": 0,
        "excluded_kev_vuln_counter": 0,
        "excluded_vuln_counter": 0,
        "excluded_misconf_counter": 3,
        "excluded_exposed_secret_counter": 0,
        "vuln_counter": 5,
        "misconf_counter": 0,
        "exposed_secret_counter": 2
    },
    "tool_version": {
        "syft_version": "1.38.0",
        "semgrep_version": "1.95.0",
        "trivy_version": "0.56.2",
        "grype_version": "0.104.1",
        "cosign_version": "2.5.3",
        "patchhound_version": "0.1.30"
    },
    "ruleset": {
        "semgrep": [
            "--config=p/security-audit",
            "--config=p/ci"
        ]
    }
}
```

**Example repositorys history:**
```
{
    "repo": "test-repo",
    "history": [
        {
            "20260103_133807": {
                "commit_sha": "Null",
                "timestamp": "20260103_133807",
                "syft_sbom_hash": "6a5fd0461ed3f03cf259f6005f7e5daa43e2cfb37dbd72d0d4c116c706fd4adc",
                "trivy_sbom_hash": "fcd8b10556b8576dcd1cf73ffeb6d6cb052eb43fe6900a8aa64bc01304187036",
                "audit_trail_hash": "628a4fb2153237a46dcf034a04eeb7e02d43d8e2b76871cd9a667392766889d5",
                "summary_report_hash": "d01ecae420bcf8c7cf18eb8a57af84aeb96f92ce12ed6e8638f107c402a3f9fe",
                "vulnerabilities": {
                    "grype_critical": 0,
                    "grype_high": 0,
                    "grype_medium": 1,
                    "grype_low": 0,
                    "grype_unknown": 0,
                    "trivy_critical": 0,
                    "trivy_high": 0,
                    "trivy_medium": 1,
                    "trivy_low": 0,
                    "trivy_unknown": 0,
                    "trivy_misconfigurations": 0,
                    "trivy_secrets": 2,
                    "sast_issues": 3
                },
                "attestation": {
                    "syft_sbom_att_hash": "fa7f3e186801da86244fd9b42e7875a8a4e480b353e805c019c5a10e6e9d3706",
                    "syft_attestation_verified": true,
                    "trivy_sbom_att_hash": "79fff4e0a38fc064e6ceaf5d0fcff4b7da2ccc0773889a49a1d0bc462423e2d6",
                    "trivy_attestation_verified": true
                },
                "alerts": [
                    "Failed to send alert for test-repo. Alert webhook not set"
                ]
            }
        }
    ]
}
```

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

## Logging and Alerts

### Logs

The backend will log all interactions and failures that happen on the backend and will save them either locally or in externally configured storage. It is possible to export the logs to a third party service either through OpenTelemetry or standard HTTPS requests. 
The structure of the logs:

```
"message": "Missing authentication token", # Human readable message
"level": "error", # What the log level is
"module": "generate-pdf", # Which module that the log comes from
"client_ip": request.remote_addr, # The IP of the client that interacted with the module
```

### Alerts

Alerts get sent to the webhook that is currently configured either through the global webhook in `app-config.yaml` in `backend.alert.webhook` or one found in the repository scan data. 
The webhook that exists in the repository scan data will take priority to be used but if it cant be found the global webhook will instead be used.

Alerts will be sent out on detection of tampering, internal failure of rescan, severity threshold of vulnerability has been reached and similar actions.

---

## Cleanup

**All cleanup is disabled by default**

### Cleanup Max Entries

In `app-config.yaml` you can configure cleanup of old scan data by a max entries threshold. When this threshold is reached the backend will remove the oldest entries it can find but will keep a set amount of the newest entries which can be configured by `cleanup.cleanup_entries.max_entries`.

### Cleanup Old Entries

This cleanup setting will remove all entries that are older than a specific age but will always keep a certain amount of the newest entries which can be configured by `cleanup.cleanup_old_entries.always_keep_entries`.

---