import os
import sys
from config.expand_env_var import expand_env
from config.secret_data.get_secret_data import set_secrets_in_env

def secret_data_storage_config(app_config):
    local_secrets_storage_enabled = app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("local", {}).get("enabled", False)

    secret_manager_enabled = app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("secret_manager", {}).get("enabled", False)

    if sum([local_secrets_storage_enabled, secret_manager_enabled]) > 1:
        print("[!] More than 1 secret data storage is enabled: [backend.storage.secret_data.]")
        sys.exit(1)
    
    if secret_manager_enabled:
        os.environ["secret_manager_enabled"] = "True"
        
        os.environ["secret_manager_name"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("secret_manager", {}).get("secret_manager_name", None))
        print("[+] Secret manager set in environment")
        set_secrets_in_env(app_config)
    else:
        print("[!] Secret manager NOT set in environment. This is not recommended in production!")