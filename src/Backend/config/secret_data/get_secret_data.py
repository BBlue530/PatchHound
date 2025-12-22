import os
import boto3
import json
import base64

def read_external_secret(secret_type):
    if secret_type == "api_key":
        return os.environ.get("api_key")
    elif secret_type == "jwt_key":
        return os.environ.get("jwt_key")
    elif secret_type == "cosign_key":
        return os.environ.get("cosign_key")
    
def set_secrets_in_env(app_config):
    if os.environ.get("secret_manager_enabled", "False").lower() == "true":
        api_key_secret_name = app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("secret_manager", {}).get("aws", {}).get("secrets_name", {}).get("api_key", None)
        jwt_key_secret_name = app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("secret_manager", {}).get("aws", {}).get("secrets_name", {}).get("jwt_key", None)
        cosign_key_secret_name = app_config.get("backend", {}).get("storage", {}).get("secret_data", {}).get("secret_manager", {}).get("aws", {}).get("secrets_name", {}).get("cosign_key", None)
        
        os.environ["api_key"] = read_secret_from_secret_manager(api_key_secret_name)
        os.environ["jwt_key"] = read_secret_from_secret_manager(jwt_key_secret_name)
        os.environ["cosign_key"] = read_secret_from_secret_manager(cosign_key_secret_name)

def read_secret_from_secret_manager(secret_key_name):
    session = boto3.session.Session(
        aws_access_key_id=os.environ.get("aws_access_key_id"),
        aws_secret_access_key=os.environ.get("aws_secret_access_key"),
        region_name=os.environ.get("aws_default_region"),
    )

    secret_name = os.environ.get("secret_manager_name")

    client = session.client("secretsmanager")

    response = client.get_secret_value(SecretId=secret_name)

    if "SecretString" in response:
        secret_payload = response["SecretString"]
    else:
        secret_payload = base64.b64decode(response["SecretBinary"]).decode("utf-8")

    try:
        secret_obj = json.loads(secret_payload)
    except json.JSONDecodeError:
        raise ValueError("Secret is not valid JSON")

    if secret_key_name not in secret_obj:
        raise KeyError(f"[!] Key: '{secret_key_name}' not found in secret '{secret_name}'")

    return secret_obj[secret_key_name]