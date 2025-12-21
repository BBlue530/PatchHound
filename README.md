# PatchHound (SBOM Vulnerability Report Generator)

---

## Overview

PatchHound is an open-source **SBOM (Software Bill of Materials) vulnerability scanner** for source code and container images. It centralizes SBOMs, vulnerabilities found, and prioritization into a single workflow. 

PatchHound helps teams by:
- Generating comprehensive audit ready reports suitable for compliance and security reviews.
- Vulnerability management through exclusions allowing public comment(visible in pdf report), internal comment and scope of vulnerability.
- Reducing alert noise through exclusion management with tracked justifications.
- Producing detailed PDF summaries that include scan metadata, statistics, exclusions, tool versions, prioritized findings and when the scan/report was generated.
- Prioritizing risk by highlighting critical and CISA KEV listed vulnerabilities.

PatchHound not only scans for vulnerabilities but also supports **signing and verifying container images** ensuring integrity and supply chain security.

---

## Features

- SBOM generation ([Syft](https://github.com/anchore/syft)) + vuln scanning ([Grype](https://github.com/anchore/grype))
- [Trivy](https://github.com/aquasecurity/trivy) for misconfigs & secrets
- [Semgrep](https://github.com/semgrep/semgrep) for SAST
- Daily re scans with updated vuln DB + KEV catalog
- Signing & verification with [Cosign](https://github.com/sigstore/cosign)
- PDF reports, repo history tracking, audit trail
- Alerts via [Slack](https://slack.com/)/[Discord](https://discord.com/)
- Scan for vulnerabilities (SBOM, SAST, misconfigs, secrets)  
- Compare against CISAs [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)  
- Sign and verify container images for supply chain integrity  
- Generate PDF summary reports
- Exclusion aware summaries with justification tracking

---

## Usage

### Backend

The backend handles file ingestion, vulnerability scanning, prioritization, and storage.
It receives SBOMs, SAST reports, and Trivy results from the CLI or CI/CD pipelines, processes them, signs results, compares vulnerabilities against the CISA KEV catalog, and triggers alerts when needed.

For installation, setup, and detailed API documentation, see the [Backend README](https://github.com/BBlue530/PatchHound/blob/master/docs/backend.md#backend-patchhound).

### CLI
The CLI is a core part of the communication between the backend and user. Read more on how to use the CLI [here](https://github.com/BBlue530/PatchHound/blob/master/docs/cli-commands.md#cli-patchhound).

### Container images
Container images are available for both the backend and the CLI. These images include everything you need to get started quickly.

#### [Backend container image](https://github.com/BBlue530/PatchHound/pkgs/container/patchhound_backend):
```
docker pull ghcr.io/bblue530/patchhound_backend:latest
```
#### [CLI image](https://github.com/BBlue530/PatchHound/pkgs/container/patchhound_cli):
```
docker pull ghcr.io/bblue530/patchhound_cli:latest
```

---

## Notes

When scanning a directory (`TARGET="."`), Syft will warn about missing explicit name/version metadata. This does **not** affect scan results.

If you dont want the workflow to fail when critical vulnerabilities are found change `FAIL_ON_CRITICAL=true` to `false`

If you are scanning a container image make sure to add a secret named `PAT_TOKEN` to your repository.

1. Go to **Settings > Secrets and variables > Actions**
2. Click **New repository secret**
3. Name it: `PAT_TOKEN`
4. Paste your PAT
5. Make sure you pass the `PAT_TOKEN` secret in the [CLI](https://github.com/BBlue530/PatchHound/blob/master/docs/cli-commands.md#scan)

### Required Token Permissions

- **`read:packages`** - required to pull images
- **`repo`** - only required if you are accessing **private images** or **private repositories**

Public images only require `read:packages`.

---

# Config

The backend currently supports the AWS ecosystem for storing secrets, S3 buckets for external scan data storage, and PostgreSQL for database management. All configurations are done in [app-config.yaml](https://github.com/BBlue530/PatchHound/blob/main/src/Backend/app-config.yaml) Support for additional storage backends may be added in the future.


```
backend:
  storage:

    secret_data:
      local:
        enabled: True

      secret_manager:
        enabled: False
        secret_manager_name: "${SECRET_MANAGER_NAME}"
        secrets_name:
          api_key: "secret_api_key"
          jwt_key: "secret_jwt_key"
          cosign_key: "secret_cosign_key"
    
    token_key_database:
      local:
        enabled: True
      
      external_database:
        enabled: False
        username: "${EXTERNAL_DB_USERNAME}"
        password: "${EXTERNAL_DB_PASSWORD}"
        db_name: "${EXTERNAL_DB_NAME}"
        db_host: "${EXTERNAL_DB_HOST}"

    scan_data:
      local:
        enabled: True

      s3_bucket:
        enabled: False
        bucket: "${BUCKET}"
        bucket_key: "${BUCKET_KEY}"
        
auth:
  aws:
    enabled: False
    aws_access_key_id: "${AWS_ACCESS_KEY_ID}"
    aws_secret_access_key: "${AWS_SECRET_ACCESS_KEY}"
    aws_default_region: "${AWS_DEFAULT_REGION}"
```

---

# Docs
- [Docs](https://github.com/BBlue530/PatchHound/tree/master/docs).
- [quick-start](https://github.com/BBlue530/PatchHound/blob/master/docs/quick-start.md)
- [backend](https://github.com/BBlue530/PatchHound/blob/main/docs/backend.md)
- [cli-commands](https://github.com/BBlue530/PatchHound/blob/main/docs/cli-commands.md)

---

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

---