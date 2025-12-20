import os
import boto3
import json

def read_external_secret(secret_type):
    if secret_type == "api_key":
        return os.environ.get("api_key")
    elif secret_type == "jwt_key":
        return os.environ.get("jwt_key")
    elif secret_type == "cosign_key":
        return os.environ.get("cosign_key")
    
def set_secrets_in_env(app_config):
    if os.environ.get("login_secret_manager_enabled", "False").lower() == "true":
        api_key_secret_name = app_config.get("backend", {}).get("storage", {}).get("login", {}).get("secret_data", {}).get("secret_manager", {}).get("secrets_name", {}).get("api_key", None)
        jwt_key_secret_name = app_config.get("backend", {}).get("storage", {}).get("login", {}).get("secret_data", {}).get("secret_manager", {}).get("secrets_name", {}).get("jwt_key", None)
        cosign_key_secret_name = app_config.get("backend", {}).get("storage", {}).get("login", {}).get("secret_data", {}).get("secret_manager", {}).get("secrets_name", {}).get("cosign_key", None)
        
        os.environ["api_key"] = read_login_secret_from_secret_manager(api_key_secret_name)
        os.environ["jwt_key"] = read_login_secret_from_secret_manager(jwt_key_secret_name)
        os.environ["cosign_key"] = read_login_secret_from_secret_manager(cosign_key_secret_name)

def read_login_secret_from_secret_manager(secret_name):
    session = boto3.session.Session(
        aws_access_key_id=os.environ.get("aws_access_key_id"),
        aws_secret_access_key=os.environ.get("aws_secret_access_key"),
        region_name=os.environ.get("aws_default_region"),
    )

    client = session.client("secretsmanager")

    response = client.get_secret_value(SecretId=secret_name)

    raw_secret_value = response.get("SecretString") or response.get("SecretBinary")

    try:
        obj = json.loads(raw_secret_value)
        return next(iter(obj.values()))

    except json.JSONDecodeError:
        return raw_secret_value