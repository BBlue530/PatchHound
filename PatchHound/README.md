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
patchhound config set <KEY> <VALUE>
```
You can update multiple keys in one command by chaining them:
```
patchhound config set <KEY1> <VALUE1> <KEY2> <VALUE2>
```
   ```bash
   # Example config to scan a container image
   TARGET="ghcr.io/<your-name>/<your-image>"
   SCAN_IMAGE=true
   FAIL_ON_CRITICAL=true
   BASE_URL="https://<your-backend>"
   ALERT_WEBHOOK="https://<your-webhook>"
   ```
   
   or to scan the current repository directory:

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
patchhound config get <KEY>
```
#### List all settings
Show all keys and their values:
```
patchhound config list
```

### Scan
`patchhound scan` runs the vulnerability scanning.
Scan is designed for use in a pipeline and might not work properly if used outside of one.
```
patchhound scan
```

### Health
Check the backends health status and version with this command:
```
patchhound health
```

### Create
Create a new token key for an organization with a specified expiration period:
```
patchhound create org <organization> exp <expiration_days>
```

### Change
Enable or disable a specific token keys:
```
patchhound change token <TOKEN_KEY> <enable|disable>
```
### Resources
PatchHound saves all resources ingested by it in a organized system and will return a path to the resources in the form of a path token.
Example path token to access resources (**this token is not sensitive and can be shared**)
```
[+] Path Token to access resources sent to backend: ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnZjbWRoYm1sNllYUnBiMjRp
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

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

---