from flask import request, jsonify, Blueprint
from database.create_key import create_key
from database.remove_key import remove_key
from database.key_status import enable_key, disable_key
from database.list_key import list_all_keys
from utils.secrets_manager import verify_api_key
from logs.event_handler import event
from core.variables import log_type_info, log_type_debug, log_type_error, log_message_key, log_level_key, log_module_key, log_details_key

token_key_bp = Blueprint("token_key", __name__)

@token_key_bp.route('/v1/create-token-key', methods=['POST'])
def create_token_key():

    api_key = request.form.get("api_key")
    if not api_key:
        event(False, {
            log_message_key: "missing authentication key",
            log_level_key: log_type_info,
            log_module_key: "create_token_key",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "api_key missing"}), 401
    response, valid = verify_api_key(api_key)
    if valid == False:
        event(False, {
            log_message_key: "invalid authentication key",
            log_level_key: log_type_info,
            log_module_key: "create_token_key",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return response

    organization = request.form.get("organization")
    if not organization:
        event(False, {
            log_message_key: "organization missing",
            log_level_key: log_type_info,
            log_module_key: "create_token_key",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "organization missing"}), 400
    
    expiration_days = request.form.get("expiration_days")
    if not expiration_days:
        event(False, {
            log_message_key: "expiration days missing",
            log_level_key: log_type_info,
            log_module_key: "create_token_key",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "expiration_days missing"}), 400
    try:
        expiration_days = int(expiration_days)
    except ValueError:
        event(False, {
            log_message_key: "invalid expiration days not integer",
            log_level_key: log_type_info,
            log_module_key: "create_token_key",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "expiration_days must be an integer"}), 400

    response = create_key(organization, expiration_days)
    event(False, {
        log_message_key: "create token key endpoint called",
        log_level_key: log_type_info,
        log_module_key: "create_token_key",
        log_details_key: {
            "client_ip": request.remote_addr,
        }
    })
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
        event(False, {
            log_message_key: "missing authentication key",
            log_level_key: log_type_info,
            log_module_key: "change_token_key_status",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "api_key missing"}), 401
    response, valid = verify_api_key(api_key)
    if valid == False:
        event(False, {
            log_message_key: "invalid authentication key",
            log_level_key: log_type_info,
            log_module_key: "change_token_key_status",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return response

    if instructions == "enable":
        response = enable_key(token_key)
        event(False, {
            log_message_key: "token key enabled",
            log_level_key: log_type_info,
            log_module_key: "change_token_key_status",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return response
    
    elif instructions == "disable":
        event(False, {
            log_message_key: "token key disable",
            log_level_key: log_type_info,
            log_module_key: "change_token_key_status",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        response = disable_key(token_key)
        return response
    
@token_key_bp.route('/v1/remove-token-key', methods=['POST'])
def remove_token_key():

    api_key = request.form.get("api_key")
    if not api_key:
        event(False, {
            log_message_key: "missing authentication key",
            log_level_key: log_type_info,
            log_module_key: "remove_token_key",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "api_key missing"}), 401
    
    response, valid = verify_api_key(api_key)

    if valid == False:
        event(False, {
            log_message_key: "invalid authentication key",
            log_level_key: log_type_info,
            log_module_key: "remove_token_key",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return response

    token_key = request.form.get("token_key")
    if not token_key:
        event(False, {
            log_message_key: "missing token key",
            log_level_key: log_type_info,
            log_module_key: "remove_token_key",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "token_key missing"}), 400

    response = remove_key(token_key)
    event(False, {
        log_message_key: "token key removed",
        log_level_key: log_type_info,
        log_module_key: "remove_token_key",
        log_details_key: {
            "client_ip": request.remote_addr,
        }
    })
    return response

@token_key_bp.route('/v1/list-token-key', methods=['POST'])
def list_token_key():

    api_key = request.form.get("api_key")
    if not api_key:
        event(False, {
            log_message_key: "missing authentication key",
            log_level_key: log_type_info,
            log_module_key: "remove_token_key",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "api_key missing"}), 401
    response, valid = verify_api_key(api_key)
    if valid == False:
        event(False, {
            log_message_key: "invalid authentication key",
            log_level_key: log_type_info,
            log_module_key: "remove_token_key",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return response

    response = list_all_keys()
    event(False, {
        log_message_key: "list token key endpoint called",
        log_level_key: log_type_info,
        log_module_key: "remove_token_key",
        log_details_key: {
            "client_ip": request.remote_addr,
        }
    })
    return response