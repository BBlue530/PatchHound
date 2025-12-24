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

def read_secret_from_secret_manager(secret_key_name, secret_name):
    session = boto3.session.Session(
        aws_access_key_id=os.environ.get("aws_access_key_id"),
        aws_secret_access_key=os.environ.get("aws_secret_access_key"),
        region_name=os.environ.get("aws_default_region"),
    )

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