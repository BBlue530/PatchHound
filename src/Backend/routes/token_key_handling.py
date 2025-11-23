from flask import request, jsonify, Blueprint
from database.create_key import create_key
from database.key_status import enable_key, disable_key
from validation.secrets_manager import verify_api_key

token_key_bp = Blueprint("token_key", __name__)

@token_key_bp.route('/v1/create-token-key', methods=['POST'])
def create_token_key():

    api_key = request.form.get("api_key")
    if not api_key:
        return jsonify({"error": "api_key missing"}), 401
    response, valid = verify_api_key(api_key)
    if valid == False:
        return response

    organization = request.form.get("organization")
    if not organization:
        return jsonify({"error": "organization missing"}), 400
    
    expiration_days = request.form.get("expiration_days")
    if not expiration_days:
        return jsonify({"error": "expiration_days missing"}), 400
    try:
        expiration_days = int(expiration_days)
    except ValueError:
        return jsonify({"error": "expiration_days must be an integer"}), 400

    response = create_key(organization, expiration_days)
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
        return jsonify({"error": "api_key missing"}), 401
    response, valid = verify_api_key(api_key)
    if valid == False:
        return response

    if instructions == "enable":
        response = enable_key(token_key)
        return response
    
    elif instructions == "disable":
        response = disable_key(token_key)
        return response