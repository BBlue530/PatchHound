# CLI PatchHound

---

## Features

- Run vulnerability scans using SBOM, SAST, and container scanning tools in one command
- Manage configuration for backend connection and scan settings
- Check backend health before running scans
- Create and manage API token keys for authenticated scans and resource access
- Retrieve stored scan artifacts by listing or downloading from the backend
- Enable/disable token keys without deleting them

---

## Usage

### Config
Patchhound uses a `scan.config` file to store variables and scan settings.

#### Set values
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
   # Example config to scan a current repository
   TARGET="."
   SCAN_IMAGE=false
   FAIL_ON_CRITICAL=true
   BASE_URL="https://<your-backend>"
   ALERT_WEBHOOK="https://<your-webhook>"
   ```

   `BASE_URL` is the url of your backend (**MANDATORY**).

   `ALERT_WEBHOOK` is the webhook you will get alerts. If its not set you will not receive alerts.

#### Get a single value
Retrieve the current value for a specific key:
```
patchhound config --get <KEY>
```
#### List all settings
Show all keys and their values:
```
patchhound config --list
```

### Scan
`patchhound scan` runs the vulnerability scanning.
Scan is designed for use in a pipeline and might not work properly if used outside of one.
```
patchhound scan --token <TOKEN>
```
If your scanning a private image you will need to pass a `PAT_TOKEN` for your registry.
```
patchhound scan --token <TOKEN> --pat <PAT_TOKEN>
```

### Health
Check the backends health status and version with this command:
```
patchhound health
```

### Create
Create a new token key for an organization with a specified expiration period:
```
patchhound create --org <organization> --exp <expiration_days>
```

### Change
Enable or disable a specific token keys:
```
patchhound change --token <TOKEN_KEY> --ins <enable|disable>
```

### Exclusions
You can exclude CVEs found in your workflow and attach a comment explaining the exclusion:
```
patchhound exclude --cve <CVE_ID> --comment <COMMENT_FOR_EXCLUSION>
```
To view all current exclusions in the `exclusions.json` file in the current directory:
```
patchhound exclude --list
```
To remove an exclusion by CVE ID:
```
patchhound exclude --remove <CVE_ID>
```
Excluding a CVE means that if it is found, it will not trigger alerts and will appear in a separate part of the summary.
Exclusions affect the entire repository and persist across versions. To update the exclusion file, simply edit the existing file and replace it with the updated version.

### Resources
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

#### List resources
To list all stored available resources in the directory:
```
patchhound resource list --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> 
``` 

#### Get resources
To download all stored available resources in the directory:

```
patchhound resource get --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> 
```
To download specific stored available resources in the directory:

```
patchhound resource get --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> [file1 file2 ...]
```
---
## Usage in pipeline

For usage in a pipeline you can refer to the workflow in this repo [here](https://github.com/BBlue530/PatchHound_Advanced/blob/master/.github/workflows/secure-pipeline.yml)

---

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

---