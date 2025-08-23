from core.variables import secret_storage, length
from config import LOCAL_SECRETS, AWS_SECRETS, AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SECRET_NAME
import json
import secrets
import os
import boto3
    
def read_secret(secret_type):
    if LOCAL_SECRETS == True:
        secret_value = read_secret_local(secret_type)
        return secret_value
    elif AWS_SECRETS == True:
        secret_value = read_secret_aws(secret_type)
        return secret_value

def verify_api_key(api_key):
    if not os.path.isfile(secret_storage):
        print("[!] Secret storage not found")
        valid = False
        response = ("Secrets not found", 404)
        return response, valid

    secret_type = "api_key"

    if LOCAL_SECRETS == True:
        stored_api_key = read_secret_local(secret_type)
    elif AWS_SECRETS == True:
        stored_api_key = read_secret_aws(secret_type)

    if not stored_api_key:
        print("[!] API key not found")
        valid = False
        response = ("API key not found in secrets", 404)
        return response, valid

    if api_key == stored_api_key:
        valid = True
        response = ("API key valid", 200)
    else:
        valid = False
        response = ("Invalid API key", 401)

    return response, valid

def read_secret_local(secret_type):
    if not os.path.isfile(secret_storage):
        print("[!] Secrets file not found")
        return None

    try:
        with open(secret_storage, "r") as f:
            secrets_data = json.load(f)
    except json.JSONDecodeError:
        print("[!] Secrets file is invalid")
        return None

    secret_value = secrets_data.get(secret_type)
    if not secret_value:
        print(f"[!] Secret '{secret_type}' not found in file")
        return None

    return secret_value
    
def read_secret_aws(secret_type):
    client = boto3.client(
        "secretsmanager",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
    resp = client.get_secret_value(SecretId=AWS_SECRET_NAME)
    secrets_data = json.loads(resp.get("SecretString"))
    if secret_type == "api_key":
        secret_value = secrets_data.get("api_key")
    elif secret_type == "jwt_key":
        secret_value = secrets_data.get("jwt_key")
    elif secret_type == "cosign_key":
        secret_value = secrets_data.get("cosign_key")
    return secret_value

def generate_secrets():
    if LOCAL_SECRETS == True:
        dir_path = os.path.dirname(secret_storage)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        try:
            with open(secret_storage, "r") as f:
                secrets_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            secrets_data = {}

        stored_api_key = secrets_data.get("api_key")
        if not stored_api_key:
            print("[!] API key not found")
            print("[~] Generating new API key")
            api_key = secrets.token_urlsafe(length)
            secrets_data["api_key"] = api_key
            with open(secret_storage, "w") as f:
                json.dump(secrets_data, f, indent=4)
            print("======================================")
            print("[!] NEW API KEY GENERATED:")
            print(f"{api_key}")
            print("======================================")
        
        stored_cosign_key = secrets_data.get("cosign_key")
        if not stored_cosign_key:
            print("[!] Cosign key not found")
            print("[~] Generating new Cosign key")
            cosign_key = secrets.token_urlsafe(length)
            secrets_data["cosign_key"] = cosign_key
            with open(secret_storage, "w") as f:
                json.dump(secrets_data, f, indent=4)
        
        stored_jwt_key = secrets_data.get("jwt_key")
        if not stored_jwt_key:
            print("[!] JWT key not found")
            print("[~] Generating new JWT key")
            jwt_key = secrets.token_urlsafe(length)
            secrets_data["jwt_key"] = jwt_key
            with open(secret_storage, "w") as f:
                json.dump(secrets_data, f, indent=4)