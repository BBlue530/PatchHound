from core.variables import secret_storage, length
import json
import secrets
import os

def verify_api_key(api_key):
    if not os.path.isfile(secret_storage):
        print("[!] Secret storage not found")
        valid = False
        response = ("Secrets not found", 404)
        return response, valid

    with open(secret_storage, "r") as f:
        secrets = json.load(f)

    stored_api_key = secrets.get("api_key")
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

def generate_secrets():
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

def read_secret(secret_type):
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