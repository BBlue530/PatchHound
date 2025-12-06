from flask import request, jsonify, Blueprint
from database.validate_token import validate_token
from core.variables import patchhound_version

health_bp = Blueprint("health", __name__)

@health_bp.route('/v1/health-check', methods=['GET'])
def health_check():

    token_key = request.args.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = False

    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 401

    return jsonify({
        "status": "ok",
        "message": "Backend is alive",
        "version": patchhound_version
    }), 200