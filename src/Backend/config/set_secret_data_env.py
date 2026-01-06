import os
import sys
from config.helpers.expand_env_var import expand_env
from config.secret_data.get_secret_data import read_secret_from_secret_manager

def secret_data_storage_config(app_config):
    generate_local_secrets_enabled = expand_env(app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("local", {}).get("generate_secrets", {}).get("enabled", False))

    local_secrets_enabled = expand_env(app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("local", {}).get("secrets", {}).get("enabled", False))

    secret_manager_enabled = expand_env(app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("secret_manager", {}).get("aws", {}).get("enabled", False))

    if sum([generate_local_secrets_enabled, local_secrets_enabled, secret_manager_enabled]) > 1:
        print("[!] More than 1 secret data storage is enabled: [backend.storage.secret_data.]")
        sys.exit(1)
    
    if secret_manager_enabled:
        os.environ["secret_in_env_enabled"] = "True"
        
        print("[+] Secret manager set in environment")
        set_external_secrets_in_env(app_config)
    elif local_secrets_enabled:
        os.environ["secret_in_env_enabled"] = "True"

        os.environ["api_key"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("local", {}).get("secrets", {}).get("secrets_name", {}).get("api_key", None))
        os.environ["jwt_key"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("local", {}).get("secrets", {}).get("secrets_name", {}).get("jwt_key", None))
        os.environ["cosign_key"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("local", {}).get("secrets", {}).get("secrets_name", {}).get("cosign_key", None))
    else:
        print("[!] Secrets NOT set in environment. This is not recommended in production!")

def set_external_secrets_in_env(app_config):
    if os.environ.get("secret_in_env_enabled", "False").lower() == "true":
        secret_name = expand_env(app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("secret_manager", {}).get("aws", {}).get("secret_manager_name", None))

        api_key_secret_name = expand_env(app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("secret_manager", {}).get("aws", {}).get("secrets_name", {}).get("api_key", None))
        jwt_key_secret_name = expand_env(app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("secret_manager", {}).get("aws", {}).get("secrets_name", {}).get("jwt_key", None))
        cosign_key_secret_name = expand_env(app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("secret_manager", {}).get("aws", {}).get("secrets_name", {}).get("cosign_key", None))
        
        os.environ["api_key"] = read_secret_from_secret_manager(api_key_secret_name, secret_name)
        os.environ["jwt_key"] = read_secret_from_secret_manager(jwt_key_secret_name, secret_name)
        os.environ["cosign_key"] = read_secret_from_secret_manager(cosign_key_secret_name, secret_name)