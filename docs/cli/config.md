# Config PatchHound CLI

---

## Overview

PatchHound CLI supports configuration through `--set-config` and `config --set` flag to manage:

- Fail on severity threshold

- Repository information

- Scan target directory

- Backend URL

- Alert webhook

This document details all supported configuration keys, their purpose, and usage examples.

---

## Configurations Keys

### Repository scan profile and information
| Key | Description |
|:-|:-|
|`REPO_NAME`|Name of the repository. This will determine the name in scan data.(`string`)|
|`AUTHOR_NAME`|Name of the user that did the commited.(`string`)|
|`AUTHOR_EMAIL`|Email of the user that did the commited.(`string`)|
|`COMMIT_AUTHOR`|`AUTHOR_NAME` + `AUTHOR_EMAIL`.(`string`)|

### Fail severity threshold
| Key | Description |
|:-|:-|
|`FAIL_ON_VULNERABILITY`|Determines if the scan should fail on severity threshold.(`bool`)|
|`FAIL_ON_SEVERITY`|Severity threshold that the scan should fail.(`string`)|

### Scan configuration
| Key | Description |
|:-|:-|
|`TARGET`|Directory that the scan should be used on.(`string`)|
|`SCAN_IMAGE`|If your scanning an image.(`bool`)|
|`SAST_SCAN`|Option to skip SAST scan.(`bool`)|
|`TRIVY_SCAN`|Option to skip Trivy scan.(`bool`)|

### Extra configuration
| Key | Description |
|:-|:-|
|`BASE_URL`|URL PatchHound is deployed on.(`string`)|
|`ALERT_WEBHOOK`|Webhook used for alerts.(`string`)|
|`CLEANUP`|If active CLI will cleanup all files generated during scan.(`bool`)|

---