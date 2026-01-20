from flask import request, jsonify, Blueprint
from database.create_key import create_key
from database.remove_key import remove_key
from database.key_status import enable_key, disable_key
from database.list_key import list_all_keys
from utils.secrets_manager import verify_api_key
from logs.export_logs import log_exporter

token_key_bp = Blueprint("token_key", __name__)

@token_key_bp.route('/v1/create-token-key', methods=['POST'])
def create_token_key():

    api_key = request.form.get("api_key")
    if not api_key:
        new_entry = {
            "message": "Missing authentication key",
            "level": "error",
            "module": "create-token-key",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "api_key missing"}), 401
    response, valid = verify_api_key(api_key)
    if valid == False:
        new_entry = {
            "message": "Invalid authentication key",
            "level": "error",
            "module": "create-token-key",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return response

    organization = request.form.get("organization")
    if not organization:
        new_entry = {
            "message": "Organization missing",
            "level": "error",
            "module": "create-token-key",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "organization missing"}), 400
    
    expiration_days = request.form.get("expiration_days")
    if not expiration_days:
        new_entry = {
            "message": "Expiration days",
            "level": "error",
            "module": "create-token-key",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "expiration_days missing"}), 400
    try:
        expiration_days = int(expiration_days)
    except ValueError:
        new_entry = {
            "message": "Invalid expiration days. Not integer",
            "level": "error",
            "module": "create-token-key",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "expiration_days must be an integer"}), 400

    response = create_key(organization, expiration_days)
    new_entry = {
        "message": "Create token key endpoint called",
        "level": "info",
        "module": "create-token-key",
        "client_ip": request.remote_addr,
    }
    log_exporter(new_entry)
    return response

@token_key_bp.route('/v1/change-key-status', methods=['POST'])
def change_token_key_status():

    token_key = request.form.get("token")
    if not token_key:
        return jsonify({"error": "token key missing"}), 400
    
    instructions = request.form.get("instructions")
    if not instructions:
        return jsonify({"error": "instructions missing"}), 400
    
    api_key = request.form.get("api_key")
    if not api_key:
        new_entry = {
            "message": "Missing authentication key",
            "level": "error",
            "module": "change-key-status",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "api_key missing"}), 401
    response, valid = verify_api_key(api_key)
    if valid == False:
        new_entry = {
            "message": "Invalid authentication key",
            "level": "error",
            "module": "change-key-status",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return response

    if instructions == "enable":
        response = enable_key(token_key)
        new_entry = {
            "message": "Token key enabled",
            "level": "info",
            "module": "change-key-status",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return response
    
    elif instructions == "disable":
        new_entry = {
            "message": "Token key disable",
            "level": "info",
            "module": "change-key-status",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        response = disable_key(token_key)
        return response
    
@token_key_bp.route('/v1/remove-token-key', methods=['POST'])
def remove_token_key():

    api_key = request.form.get("api_key")
    if not api_key:
        new_entry = {
            "message": "Missing authentication key",
            "level": "error",
            "module": "remove-token-key",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "api_key missing"}), 401
    
    response, valid = verify_api_key(api_key)

    if valid == False:
        new_entry = {
            "message": "Invalid authentication key",
            "level": "error",
            "module": "remove-token-key",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return response

    token_key = request.form.get("token_key")
    if not token_key:
        new_entry = {
            "message": "Missing token key",
            "level": "error",
            "module": "remove-token-key",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "token_key missing"}), 400

    response = remove_key(token_key)
    new_entry = {
        "message": "Token key removed",
        "level": "info",
        "module": "remove-token-key",
        "client_ip": request.remote_addr,
    }
    log_exporter(new_entry)
    return response

@token_key_bp.route('/v1/list-token-key', methods=['POST'])
def list_token_key():

    api_key = request.form.get("api_key")
    if not api_key:
        new_entry = {
            "message": "Missing authentication key",
            "level": "error",
            "module": "list-token-key",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "api_key missing"}), 401
    response, valid = verify_api_key(api_key)
    if valid == False:
        new_entry = {
            "message": "Invalid authentication key",
            "level": "error",
            "module": "list-token-key",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return response

    response = list_all_keys()
    new_entry = {
        "message": "List token key endpoint called",
        "level": "info",
        "module": "list-token-key",
        "client_ip": request.remote_addr,
    }
    log_exporter(new_entry)
    return response