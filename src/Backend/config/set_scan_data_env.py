import os
import sys
from config.helpers.expand_env_var import expand_env

def scan_data_storage_config(app_config):
    local_storage_enabled = app_config.get("backend", {}).get("storage", {}).get("scan_data", {}).get("local", {}).get("enabled", False)

    s3_bucket_enabled = app_config.get("backend", {}).get("storage", {}).get("scan_data", {}).get("s3_bucket", {}).get("enabled", False)

    if sum([local_storage_enabled, s3_bucket_enabled]) > 1:
        print("[!] More than 1 scan data storage is enabled: [backend.storage.scan_data.]")
        sys.exit(1)
    
    if s3_bucket_enabled:
        os.environ["s3_bucket_enabled"] = "True"
        
        os.environ["s3_bucket"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("scan_data", {}).get("s3_bucket", {}).get("bucket", None))
        os.environ["s3_bucket_key"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("scan_data", {}).get("s3_bucket", {}).get("bucket_key", None))
        print("[+] S3 bucket set in environment")
    else:
        print("[!] S3 bucket NOT set in environment. This is not recommended in production!")