# CLI PatchHound

---

## Overview

PatchHound CLI provides an interface to run vulnerability scans, manage configurations and tokens, request pdf reports, handle exclusions, and sign or verify container images. Its designed to make security scanning, reporting, and workflow integration simple and automated.

---

# Features

- Run vulnerability scans using SBOM, SAST, and container scanning tools in one command
- Manage configuration for backend connection and scan settings
- Check backend health before running scans
- Create and manage token keys for authenticated scans and resource access
- Retrieve stored scan artifacts by listing or downloading from the backend
- Enable/disable token keys without deleting them
- Add and remove exclusions of vulnerabilties
- Request a PDF summary report of a specific workflow
- Sign and verify container images

---

# Usage

---

## Config
Patchhound uses a `scan.config` file to store variables and scan settings.

### Set values
To update a variable (KEY) in the config file:
```
patchhound config --set <KEY> <VALUE>
```
You can update multiple keys in one command by chaining them:
```
patchhound config --set <KEY1> <VALUE1> <KEY2> <VALUE2>
```
If you wish for the values to be secret and not displayed after being set use `--set-secret` instead:
```
patchhound config --set-secret <KEY1> <VALUE1> <KEY2> <VALUE2>
```
   ```bash
   # Default scan.config file
   TARGET="."
   SCAN_IMAGE=false
   FAIL_ON_CRITICAL=true
   FAIL_ON_SEVERITY=CRITICAL
   BASE_URL="https://<your-backend>"
   ALERT_WEBHOOK="https://<your-webhook>"
   SAST_SCAN=true
   TRIVY_SCAN=true
   CLEANUP=true
   ```

   ```bash
   # Default scan_profile.config file
   REPO_NAME="<your-repo-name>"
   AUTHOR_NAME="<your-name>"
   AUTHOR_EMAIL="<your-email>"
   COMMIT_AUTHOR="$AUTHOR_NAME <$AUTHOR_EMAIL>"
   ```

   - `TARGET`
      The target to scan.
      By default, this is set to `.` (the current repositorys source code).
      Change this only if you want to scan a different directory or a container image.

   - `SCAN_IMAGE` (default: `false`)
      Set to `true` if scanning a container image.
      If false some image specific scans will be skipped.

   - `FAIL_ON_CRITICAL` (default: `true`)
      If `true` the pipeline will fail when critical vulnerabilities are found.

   - `FAIL_ON_SEVERITY` (default: `CRITICAL`)
      Determines which vulnerability severity will cause the pipeline to fail if detected. 
      You can use standard severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`) or numeric values corresponding to CVSS scores. 
      
      ⚠️ **Warning:** While numeric CVSS thresholds are supported use them with caution. Grypes CVSS scoring can sometimes be inconsistent or missing for certain vulnerabilities which may cause unexpected behavior when failing the pipeline based on numeric thresholds.

   - `BASE_URL` (**MANDATORY**).
      The base URL of your backend.
      This must be set or the scan will fail.

   - `ALERT_WEBHOOK` (optional)
      The webhook URL where alerts will be sent.
      If not set, you will not receive alerts.

   - `SAST_SCAN` (default: `true`)
      Set to `false` to skip the SAST (static application security testing) scan of your source code.

   - `TRIVY_SCAN` (default: `true`)
      Set to `false` to skip the Trivy scan for vulnerabilities, misconfigurations, and secrets.

   - `CLEANUP` (default: `true`)
      Set to `false` to skip cleanup of files that get created by the scans.

### Get a single value
Retrieve the current value for a specific key:
```
patchhound config --get <KEY>
```
#### List all settings
Show all values:
```
patchhound config --list
```

---

## Scan
`patchhound scan` runs the vulnerability scanning.
Scan is designed for use in a pipeline and might not work properly if used outside of one.
```
patchhound scan --token <TOKEN>
```
If your scanning a private image you will need to pass a `PAT_TOKEN` for your registry.
```
patchhound scan --token <TOKEN> --pat <PAT_TOKEN>
```

---

## Health
Check the backends health status and version with this command:
```
patchhound health --token <TOKEN_KEY>
```

---

## Create
Create a new token key for an organization with a specified expiration period:
```
patchhound create --api-key <API_KEY> --org <ORGANIZATION> --exp <EXPIRATION_DAYS>
```

---

## Change
Enable or disable a specific token keys:
```
patchhound change --api-key <API_KEY> --token <TOKEN_KEY> --ins <enable|disable>
```

---

## Exclusions
You can exclude CVEs found in your workflow and attach a comment explaining the exclusion:
```
patchhound exclude --cve <CVE_ID> --comment <COMMENT_FOR_EXCLUSION>
```
### List Exclusions List
To view all current exclusions in the `exclusions.json` file in the current directory:
```
patchhound exclude --list
```
### Remove Exclusion
To remove an exclusion by CVE ID:
```
patchhound exclude --remove <CVE_ID>
```
Excluding a CVE means that if it is found, it will not trigger alerts and will appear in a separate part of the summary.
Exclusions affect the entire repository and persist across versions. To update the exclusion file, simply edit the existing file and replace it with the updated version.

---

## Resources
PatchHound saves all resources ingested by it in a organized system and will return a path to the resources in the form of a path token.
Example path token to access resources (**this token is not sensitive and can be shared**)
```
[+] Path token
Path token to access resources sent to backend:
ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnZjbWRoYm1sNllYUnBiMjRp
T2lKMFpYTjBiM0puSWl3aVkzVnljbVZ1ZEY5eVpYQnZJam9pUWtKc2RXVTFNekJmVUdGMFkyaEli
M1Z1WkY5QlpIWmhibU5sWkNJc0luUnBiV1Z6ZEdGdGNDSTZJakl3TWpVd09EQTVYekUxTkRReU9D
SjkucnFDOHVMbG5FeGtPOEpsTlFuenlTM2RGYndXWk9YRU1Rc0M0alhYRE1fVQ==
```

### List resources
To list all stored available resources in the directory:
```
patchhound resource list --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> 
``` 

### Get resources
To download all stored available resources in the directory:

```
patchhound resource get --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> 
```
To download specific stored available resources in the directory:

```
patchhound resource get --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> [file1 file2 ...]
```

### Repo wide resources

If you want to `list` or `get` resources across the entire repository (not tied to a specific scan run), add the `--repo-resources` flag:
```
patchhound resource get --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> --repo-resources
```
```
patchhound resource list --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> --repo-resources
```

### Latest resources
To get or list the most recent resources added to a repository use the `--latest` flag with your command:
#### Get the latest resource:
```
patchhound resource get --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> --latest
```
#### List the latest resources:
```
patchhound resource list --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> --latest
``` 

---

### PDF summary report
You can generate a complete summary report in PDF format using the pdf command:
```
patchhound resource pdf --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> 
``` 
Download the PDF report to your local machine and save a copy of the report in the same directory where the summary was extracted.

---

## Container image signing and verifying
Patchhound can sign and verify container images within your workflow to ensure that the image you are using is the exact one that was originally signed.

### Sign image
You can sign an image using the CLI. This generates a signature for the pulled image which can later be used to verify its integrity.
```
patchhound image sign --image <IMAGE_NAME> --token <TOKEN> --pat <PAT_TOKEN(needed for private images)>
``` 
This command outputs a path token which you will need for image verification.

### Verify image
To verify an image you will have to provide the same path token you got when signing the image.
```
patchhound image verify --image <IMAGE_NAME> --token <TOKEN> --pat <PAT_TOKEN(needed for private images)> --path-token <PATH_TO_RESOURCES_TOKEN>
``` 
This will validate the image against the previously generated signature ensuring it has not been altered.

---

## Help
To get a list of the avaliable commands use `--help` flag.
```
patchhound --help
```
You can also get help on a specific command by using `--help` flag in combination with a command.
```
patchhound <COMMAND> --help
```

---
## Usage in pipeline

For usage in a pipeline you can refer to the workflow in this repo [here](https://github.com/BBlue530/PatchHound/blob/master/.github/workflows/patchhound-pipeline.yml)

---