# SBOM Vulnerability Report Generator

An open-source, plug-and-play **SBOM (Software Bill of Materials) vulnerability scanner** that generates comprehensive vulnerability reports for container images or source code repositories.

---

## Features

- Automatically generates an SBOM using [Syft](https://github.com/anchore/syft)
- Scans for vulnerabilities with [Grype](https://github.com/anchore/grype)
- Outputs detailed vulnerability counts by severity
- Lists top critical vulnerabilities found
- Configurable via a simple `scan.config` file
- Works on local source repos or remote container images

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

   `GHCR_PAT` is the PAT you will have to provide but is not needed if you dont intend on scanning private images.

   ```
    SBOM_SCAN_API_URL: ${{ secrets.SBOM_SCAN_API_URL }}
    ALERT_WEBHOOK: ${{ secrets.ALERT_WEBHOOK }}
    LICENSE_SECRET: ${{ secrets.LICENSE_SECRET }}
    GHCR_PAT: ${{ secrets.GHCR_PAT }}
   ```
5. Start backend by installing dependencies using `pip install -r requirements.txt` and then starting the backend with `python Main.py`.
   You can also start the application using this docker image `need to work on it`.

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

If you dont want the workflow to fail when critical vulnerabilities are found change `FAIL_ON_CRITICAL=true` to false

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

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

---
⚠️ **Warning:** Run this workflow on only one main branch to keep runs minimal and avoid GitHub Actions rate limits.
---