# Quick start PatchHound

---

## Overview

This guide gets you up and running with PatchHound in just a few simple steps. You will set configurations, run your first scan, and see how to generate reports or verify images so you can test the system.

---

## Clone the Repository

```
git clone https://github.com/BBlue530/PatchHound.git
cd PatchHound
```

## Start the Backend
Move into the backend directory and start it:
```
cd Backend
bash Start.sh
```
- Installs dependencies automatically
- Initializes the database
- Starts the vulnerability scan scheduler
Leave this running in a terminal window.

## Install the CLI
To use PatchHound CLI you will need to run `install.sh`. In a different terminal navigate back `PatchHound` directory:
```
cd PatchHound
bash install.sh
```
If `secrets.json` with valid secrets are missing the backend will generate valid values which will include an api key which you will need to `change` and `create` token keys.
Example:
```
======================================
[!] NEW API KEY GENERATED:
UmA-amMq-FaMnF_aFNegzQ5hozYjOffwy8yJVgIeV18
======================================
```

## Configure the CLI
After PatchHound CLI is installed you will need to configure it:
```
patchhound config --set BASE_URL http://localhost:8080 REPO_NAME test-repo AUTHOR_NAME Your-Name AUTHOR_EMAIL you@example.com
```
Optionally set `SAST_SCAN`, `TRIVY_SCAN`, or `SCAN_IMAGE` depending on what you want to test. You can read more about configurations of the CLI [here](https://github.com/BBlue530/PatchHound/blob/master/docs/cli-commands.md#config)

## Create a Token Key
Create a new token for your organization to authenticate scans:
```
patchhound create --api-key <api_key> --org <organization> --exp 30
```
- Replace `<api_key>` with the api key your backend provided you
- Replace `<organization>` with your org name
- `--exp 30` sets the token to expire in 30 days
- Copy the token output you will need it for scanning

## Run a Scan
By default will PatchHound attempt to scan the current directory which can be changed in the config:
```
patchhound config --set TARGET <directory-or-image-you-want-scanned>
```
To scan the `TARGET`:
```
patchhound scan --token <TOKEN>
```
- Replace `<TOKEN>` with the token you created in step 3.
- For private container images, add --pat `<PAT_TOKEN>`.
Once the scan is finished it will give you a `<PATH_TO_RESOURCES_TOKEN>` which will be needed later.

Example path token to access resources (**this token is not sensitive and can be shared**)
```
[+] Path token
Path token to access resources sent to backend:
ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnZjbWRoYm1sNllYUnBiMjRp
T2lKMFpYTjBiM0puSWl3aVkzVnljbVZ1ZEY5eVpYQnZJam9pUWtKc2RXVTFNekJmVUdGMFkyaEli
M1Z1WkY5QlpIWmhibU5sWkNJc0luUnBiV1Z6ZEdGdGNDSTZJakl3TWpVd09EQTVYekUxTkRReU9D
SjkucnFDOHVMbG5FeGtPOEpsTlFuenlTM2RGYndXWk9YRU1Rc0M0alhYRE1fVQ==
```

## View Results
To list all stored available resources in the directory:
```
patchhound resource list --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN>
```
To download all stored available resources in the directory:
```
patchhound resource get --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> 
```

## PDF reports
You can generate a complete summary report in PDF format using the pdf command:
```
patchhound resource pdf --token <TOKEN> --path-token <PATH_TO_RESOURCES_TOKEN> 
``` 

## (Optional) Container image sign/verify
### Sign image
To sign an image:
```
patchhound image sign --image <IMAGE_NAME> --token <TOKEN> --pat <PAT_TOKEN(needed for private images)>
``` 
This command outputs a path token which you will need for image verification.

### Verify image
To verify an image:
```
patchhound image verify --image <IMAGE_NAME> --token <TOKEN> --pat <PAT_TOKEN(needed for private images)> --path-token <PATH_TO_RESOURCES_TOKEN>
``` 
This will validate the image against the previously generated signature ensuring it has not been altered.

---

# Conclusion
PatchHound makes it simple to scan for vulnerabilities, manage tokens, and generate reports all from the CLI. After completing this quick start, you should be able to run your first scan, retrieve results, and optionally sign or verify container images.

For more in-depth information:
- Learn more about the Backend [here](https://github.com/BBlue530/PatchHound/blob/master/docs/backend.md#backend-patchhound)
- Learn more about the CLI [here](https://github.com/BBlue530/PatchHound/blob/master/docs/cli-commands.md#cli-patchhound)

---