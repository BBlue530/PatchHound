from flask import request, jsonify, Blueprint
from database.validate_token import validate_token
from logs.export_logs import log_exporter
from core.variables import patchhound_version

health_bp = Blueprint("health", __name__)

@health_bp.route('/v1/health-check', methods=['GET'])
def health_check():

    token_key = request.args.get("token")
    if not token_key:
        new_entry = {
            "message": "Missing authentication token",
            "level": "error",
            "module": "health",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = False

    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        new_entry = {
            "message": f"Invalid token provided: {token_key}",
            "level": "error",
            "module": "health",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": f"{response}"}), 401

    new_entry = {
        "message": "Health check endpoint called",
        "level": "info",
        "module": "health",
        "client_ip": request.remote_addr,
    }
    log_exporter(new_entry)

    return jsonify({
        "status": "ok",
        "message": "Backend is alive",
        "version": patchhound_version
    }), 200