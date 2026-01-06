# Config PatchHound

---

## Overview

PatchHound supports configuration through `app-config.yaml` to manage:

- Secrets storage (local or AWS Secret Manager)

- Token key database (local or external PostgreSQL)

- Scan data storage (local or S3)

- Authentication for cloud services (currently AWS)

This document details all supported configuration keys, their purpose, and usage examples.

---

## Configurations Keys

### General Config
| Key | Description |
|:-|:-|
|`local`|Enables local storage or settings.|
|`enabled`|Used to enable or disable a feature. (`true` or `false`).|
|`auth`|Configuration for authentication to external cloud resources.|
|`secret_data`|Manages secrets for the backend. Can be local or via AWS Secret Manager.|
|`token_key_database`|Configuration for the token key database (local or external).|
|`scan_data`|Configuration for storing scan results. Can be local or in S3.|

### Secrets Config
| Key | Description |
|:-|:-|
|`secret_data.local.generate_secrets`|When `generate_secrets` is enabled the backend will verify secrets exist on the system and generate any missing. This is not recommended for production since it will have the secrets writen on the disk.|
|`secret_data.local.secrets`|When `secrets` is enabled the backend will ingest environment variables that exist on the system.|

### AWS Config
| Key | Description |
|:-|:-|
|`auth.aws`|AWS authentication settings.|
|`secret_manager.aws`|AWS Secret Manager configuration.|
|`secret_manager.aws.secret_manager_name`|Name of the AWS Secret Manager.|
|`secret_manager.aws.secrets_name.api_key`|Key name for stored API keys.|
|`secret_manager.aws.secrets_name.jwt_key`|Key name for stored JWT keys.|
|`secret_manager.aws.secrets_name.cosign_key`|Key name for stored Cosign password which is used to encrypt the private key.|
|`scan_data.s3_bucket.bucket`|Name of the S3 bucket for scan data storage.|
|`scan_data.s3_bucket.bucket_key`|Optional prefix/key inside the S3 bucket.|

### External Database Config
| Key | Description |
|:-|:-|
|`token_key_database.external_database.username`|PostgreSQL username.|
|`token_key_database.external_database.password`|PostgreSQL password|
|`token_key_database.external_database.db_name`|PostgreSQL database name|
|`token_key_database.external_database.db_host`|PostgreSQL host address.|

### Log Export Config
| Key | Description |
|:-|:-|
|`export_log.https.export_url`|The url that PatchHound will send service logs to.|
|`export_log.https.export_url_api_key`|API key used to authenticate with the export url.|
|`export_log.opentelemetry.export_url`|The OpenTelemetry url that PatchHound will send all logs to.|
|`export_log.opentelemetry.export_url_api_key`|API key used to authenticate with OpenTelemetry.|
|`export_log.opentelemetry.service_name`|The name of the service the logs will be under in OpenTelemetry.|
|`export_log.opentelemetry.environment`|The environment the service will be under in OpenTelemetr.|

---