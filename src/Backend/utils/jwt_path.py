import jwt
from jwt import InvalidTokenError
from utils.secrets_manager import read_secret
from logs.event_handler import event
from core.variables import log_type_info, log_type_debug, log_type_error, log_message_key, log_level_key, log_module_key, log_details_key

def jwt_path_to_resources(audit_trail, organization ,current_repo, timestamp):
    repo_name = current_repo.replace("/", "_")
    payload = {
    "organization": organization,
    "current_repo": repo_name,
    "timestamp": timestamp
    }
    secret_type = "jwt_key"
    jwt_secret = read_secret(secret_type)
    path_to_resources_token = jwt.encode(payload, jwt_secret, algorithm="HS256")

    event(audit_trail, {
        log_message_key: "jwt token created for path to resources",
        log_level_key: log_type_debug,
        log_module_key: "jwt_path_to_resources",
        log_details_key: {
            "organization": organization,
            "current_repo": repo_name,
            "timestamp": timestamp
        }
    })
    return path_to_resources_token

def decode_jwt_path_to_resources(path_to_resources_token, organization):
    try:
        secret_type = "jwt_key"
        jwt_secret = read_secret(secret_type)
        decoded_data = jwt.decode(path_to_resources_token, jwt_secret, algorithms=["HS256"])

        if decoded_data.get("organization") != organization:
            valid = False
            return None, None, None, valid
        
        organization_decoded = decoded_data.get("organization")
        current_repo_decoded = decoded_data.get("current_repo")
        timestamp_decoded = decoded_data.get("timestamp")
        valid = True

        return organization_decoded, current_repo_decoded, timestamp_decoded, valid
    
    except InvalidTokenError:
        valid = False
        return None, None, None, valid