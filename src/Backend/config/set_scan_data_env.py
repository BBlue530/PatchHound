import os
import sys
from config.helpers.expand_env_var import expand_env

def scan_data_storage_config(app_config):
    local_storage_enabled = expand_env(app_config.get("backend", {}).get("storage", {}).get("scan_data", {}).get("local", {}).get("enabled", False))

    aws_s3_bucket_enabled = expand_env(app_config.get("backend", {}).get("storage", {}).get("scan_data", {}).get("aws", {}).get("s3_bucket", {}).get("enabled", False))

    if sum([local_storage_enabled, aws_s3_bucket_enabled]) > 1:
        print("[!] More than 1 scan data storage is enabled: [backend.storage.scan_data.]")
        sys.exit(1)
    
    if aws_s3_bucket_enabled:
        os.environ["external_storage_enabled"] = "True"
        os.environ["aws_s3_bucket_enabled"] = "True"
        
        os.environ["aws_s3_bucket"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("scan_data", {}).get("aws", {}).get("s3_bucket", {}).get("bucket", None))
        os.environ["aws_s3_bucket_key"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("scan_data", {}).get("aws", {}).get("s3_bucket", {}).get("bucket_key", None))
        print("[+] AWS s3 set in environment")
    else:
        print("[!] AWS s3 NOT set in environment. This is not recommended in production!")