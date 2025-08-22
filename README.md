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
- Configurable via CLI
- Works on source repos or remote and local container images
- Supports multiple concurrent scans with worker-based processing
- CLI for interacting with the backend
- Exclusion of vulnerabilities in workflow that carry across versions
- PDF summary report of the workflow
- Signing and verifying of container images

---

## Usage

# Backend

The backend handles file ingestion, vulnerability scanning, prioritization, and storage.
It receives SBOMs, SAST reports, and Trivy results from the CLI or CI/CD pipelines, processes them, signs results, compares vulnerabilities against the CISA KEV catalog, and triggers alerts when needed.

For installation, setup, and detailed API documentation, see the [Backend README](https://github.com/BBlue530/PatchHound/blob/master/docs/backend.md#backend-patchhound).

# CLI
The CLI is a core part of the communication between the backend and user. Read more on how to use the CLI [here](https://github.com/BBlue530/PatchHound/blob/master/docs/cli-commands.md#cli-patchhound).

## What you can expect:
```
===============================================
          PatchHound - by BBlue530
===============================================
[~] Generating Summary
[i] Vulnerability assessment::
----------------------------------------------------------------------
[+] Grype Results::
Critical: 18
High: 38
Medium: 28
Low: 3
Unknown: 0
----------------------------------------------------------------------
[+] Trivy Results::
Critical: 18
High: 38
Medium: 28
Low: 3
Unknown: 0
Misconfigurations: 0
Exposed Secrets: 0
----------------------------------------------------------------------
[+] SAST Results::
Critical: 1
Issues: 2
----------------------------------------------------------------------
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

# Docs
If PatchHound is something that looks interesting you can learn more about it [here](https://github.com/BBlue530/PatchHound/tree/master/docs).
You can also test PatchHound by following the [quick-start](https://github.com/BBlue530/PatchHound/blob/master/docs/quick-start.md) documentation.

---

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

---

⚠️ **Warning: PatchHound is currently in development. There is no stable release yet.**  
Use at your own risk and expect potential breaking changes until a stable version is released.

---