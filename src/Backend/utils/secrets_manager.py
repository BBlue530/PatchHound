import json
import secrets
import os
import sys
from utils.helpers import load_file_data
from config.secret_data. get_secret_data import read_external_secret
from logs.event_handler import event
from core.variables import secret_storage, length, secret_types, log_type_info, log_type_debug, log_type_error, log_message_key, log_level_key, log_module_key, log_details_key
    
def read_secret(secret_type):
    if os.environ.get("secret_in_env_enabled", "False").lower() == "true":
        secret_value = read_external_secret(secret_type)
        return secret_value
    else:
        secret_value = read_secret_local(secret_type)
        return secret_value

def verify_api_key(api_key):
    secret_type = "api_key"

    if os.environ.get("secret_in_env_enabled", "False").lower() == "true":
        stored_api_key = read_external_secret(secret_type)
    else:
        if not os.path.isfile(secret_storage):
            print("[!] Secret storage not found")
            valid = False
            response = ("Secrets not found", 404)
            return response, valid
        stored_api_key = read_secret_local(secret_type)

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
        event(False, {
            log_message_key: "secret file not found",
            log_level_key: log_type_error,
            log_module_key: "read_secret_local",
            log_details_key: {
                "": ""
            }
        })
        return None

    try:
        secrets_data = load_file_data(secret_storage)
    except json.JSONDecodeError:
        event(False, {
            log_message_key: "secret file is invalid",
            log_level_key: log_type_error,
            log_module_key: "read_secret_local",
            log_details_key: {
                "": ""
            }
        })
        return None

    secret_value = secrets_data.get(secret_type)
    if not secret_value:
        event(False, {
            log_message_key: "secret does not exist",
            log_level_key: log_type_error,
            log_module_key: "read_secret_local",
            log_details_key: {
                "secret_type": "secret_type"
            }
        })
        return None

    return secret_value

def generate_secrets():
    if os.environ.get("secret_in_env_enabled", "False").lower() != "true":
        dir_path = os.path.dirname(secret_storage)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        try:
            secrets_data = load_file_data(secret_storage)
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

def verify_secrets():
    if os.environ.get("secret_in_env_enabled", "False").lower() == "true":
        # I know this isnt the best way to do this buts its a temp thing
        api_key = os.environ.get("api_key")
        jwt_key = os.environ.get("jwt_key")
        cosign_key = os.environ.get("cosign_key")
        if not api_key:
            print("[!] External secret in env [api_key]")
            sys.exit(1)
        elif not jwt_key:
            print("[!] External secret in env [jwt_key]")
            sys.exit(1)
        elif not cosign_key:
            print("[!] External secret in env [cosign_key]")
            sys.exit(1)
        print("[+] External secret set")
    else:
        for secret_type in secret_types:
            secret_value = read_secret(secret_type)
            if not secret_value:
                print(f"[!] Secret missing in local [{secret_types}]")
                sys.exit(1)