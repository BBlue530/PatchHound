import os
import sys
from config.helpers.expand_env_var import expand_env

def database_storage_config(app_config):
    local_database_enabled = expand_env(app_config.get("backend", {}).get("storage", {}).get("token_key_database", {}).get("local", {}).get("enabled", False))

    external_database_enabled = expand_env(app_config.get("backend", {}).get("storage", {}).get("token_key_database", {}).get("external_database", {}).get("enabled", False))

    if sum([local_database_enabled, external_database_enabled]) > 1:
        print("[!] More than 1 database storage is enabled: [backend.storage.token_key_database.]")
        sys.exit(1)
    
    if external_database_enabled:
        os.environ["external_database_enabled"] = "True"
        
        os.environ["external_database_username"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("token_key_database", {}).get("external_database", {}).get("username", None))
        os.environ["external_database_password"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("token_key_database", {}).get("external_database", {}).get("password", None))
        os.environ["external_database_name"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("token_key_database", {}).get("external_database", {}).get("db_name", None))
        os.environ["external_database_host"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("token_key_database", {}).get("external_database", {}).get("db_host", None))
        print("[+] External database set in environment")
    else:
        print("[!] External database NOT set in environment. This is not recommended in production!")