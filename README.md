# PatchHound (SBOM Vulnerability Report Generator)

---

## Overview

An open-source, plug-and-play **SBOM (Software Bill of Materials) vulnerability scanner** that generates comprehensive vulnerability reports for container images or source code repositories. 

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

# Docs
- [Docs](https://github.com/BBlue530/PatchHound/tree/master/docs).
- [quick-start](https://github.com/BBlue530/PatchHound/blob/master/docs/quick-start.md)
- [backend](https://github.com/BBlue530/PatchHound/blob/main/docs/backend.md)
- [cli-commands](https://github.com/BBlue530/PatchHound/blob/main/docs/cli-commands.md)

---

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

---

⚠️ **Warning: PatchHound is currently in development. There is no stable release yet.**  
Use at your own risk and expect potential breaking changes until a stable version is released.

---