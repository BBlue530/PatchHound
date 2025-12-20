import os
import sys
from config.helpers.expand_env_var import expand_env

def aws_auth(app_config):
    aws_auth_enabled = app_config.get("auth", {}).get("aws", {}) .get("enabled", False)

    if sum([aws_auth_enabled]) > 1:
        print("[!] More than 1 auth is enabled: [auth.]")
        sys.exit(1)

    if aws_auth_enabled:
        os.environ["aws_access_key_id"] = expand_env(app_config.get("auth", {}).get("aws", {}) .get("aws_access_key_id", None))
        os.environ["aws_secret_access_key"] = expand_env(app_config.get("auth", {}).get("aws", {}) .get("aws_secret_access_key", None))
        os.environ["aws_default_region"] = expand_env(app_config.get("auth", {}).get("aws", {}) .get("aws_default_region", None))
        print("[+] Auth set in environment")
    else:
        print("[!] Auth NOT set in environment. This is not recommended in production!")