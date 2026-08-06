from flask import request, jsonify, Blueprint
import hashlib
from database.validate_token import validate_token
from logs.event_handler import event
from core.variables import patchhound_version, log_type_info, log_type_debug, log_type_error, log_message_key, log_level_key, log_module_key, log_details_key

health_bp = Blueprint("health", __name__)

@health_bp.route('/v1/health-check', methods=['GET'])
def health_check():
    audit_trail = False

    token_key = request.args.get("token")
    if not token_key:
        event(audit_trail, {
            log_message_key: "missing authentication token",
            log_level_key: log_type_info,
            log_module_key: "health_check",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "Token missing"}), 401

    response, valid_token = validate_token(audit_trail, hashlib.sha256(token_key.encode("utf-8")).hexdigest())
    if valid_token == False:
        event(audit_trail, {
            log_message_key: "invalid token provided",
            log_level_key: log_type_info,
            log_module_key: "health_check",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": f"{response}"}), 401

    event(audit_trail, {
        log_message_key: "health check endpoint called",
        log_level_key: log_type_info,
        log_module_key: "health_check",
        log_details_key: {
            "client_ip": request.remote_addr,
        }
    })

    return jsonify({
        "status": "ok",
        "message": "Backend is alive",
        "version": patchhound_version
    }), 200