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

| Key | Description |
|:-|:-|
|`local`|Enables local storage or settings.|
|`enabled`|Used to enable or disable a feature. (`true` or `false`)|
|`auth`|Configuration for authentication to external cloud resources.|
|`auth.aws`|AWS authentication settings.|
|`secret_data`|Manages secrets for the backend. Can be local or via AWS Secret Manager.|
|`secret_manager.aws`|AWS Secret Manager configuration.|
|`secret_manager.aws.secret_manager_name`|Name of the AWS Secret Manager.|
|`secret_manager.aws.secrets_name.api_key`|Key name for storing API keys.|
|`secret_manager.aws.secrets_name.jwt_key`|Key name for storing JWT keys.|
|`secret_manager.aws.secrets_name.cosign_key`|Key name for storing Cosign password which is used to encrypt the private key.|
|`token_key_database`|Configuration for the token key database (local or external).|
|`token_key_database.external_database.username`|PostgreSQL username.|
|`token_key_database.external_database.password`|PostgreSQL password|
|`token_key_database.external_database.db_name`|PostgreSQL database name|
|`token_key_database.external_database.db_host`|PostgreSQL host address.|
|`scan_data`|Configuration for storing scan results. Can be local or in S3.|
|`scan_data.s3_bucket.bucket`|Name of the S3 bucket for scan data storage.|
|`scan_data.s3_bucket.bucket_key`|Optional prefix/key inside the S3 bucket.|

---