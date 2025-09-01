from flask import request, jsonify, Blueprint
from datetime import datetime
from file_system.image_signature import sign_image_digest, verify_image_digest, sign_base_image_digest, verify_base_image_digest
from utils.jwt_path import jwt_path_to_resources, decode_jwt_path_to_resources
from database.validate_token import validate_token

image_bp = Blueprint("image", __name__)

@image_bp.route('/v1/verify-image', methods=['POST'])
def verify_image():
    
    token_key = request.form.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = []

    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 401
    organization = response

    missing_fields = []
    if not request.form.get("image_digest"):
        missing_fields.append("image digest")
    if not request.form.get("path_to_resources_token"):
        missing_fields.append("path to resources token")

    if missing_fields:
        return jsonify({"error": f"Missing: {', '.join(missing_fields)}"}), 400

    image_digest = request.form.get("image_digest")
    path_to_resources_token = request.form.get("path_to_resources_token")

    if not path_to_resources_token:
        return jsonify({"error": "path_to_resources_token missing"}), 400
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)
    
    if valid == True:
        verify_image_status = verify_image_digest(audit_trail, image_digest, organization_decoded, current_repo_decoded, timestamp_decoded)
        return verify_image_status
    else:
        return jsonify({"error": "invalid jwt token"}), 404

@image_bp.route('/v1/sign-image', methods=['POST'])
def sign_images():
    
    token_key = request.form.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = []

    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 401
    organization = response

    missing_fields = []
    if not request.form.get("image_digest"):
        missing_fields.append("image digest")
    if not request.form.get("current_repo"):
        missing_fields.append("current repo")

    if missing_fields:
        return jsonify({"error": f"Missing: {', '.join(missing_fields)}"}), 400

    image_digest = request.form.get("image_digest")
    current_repo = request.form.get("current_repo")

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path_to_resources_token = jwt_path_to_resources(audit_trail, organization ,current_repo, timestamp)

    result, status_code = sign_image_digest(audit_trail, image_digest, organization, current_repo, timestamp)
    return jsonify({"message": result, "path_to_resources_token": path_to_resources_token, "status": status_code}), status_code

@image_bp.route('/v1/sign-base-image', methods=['POST'])
def sign_base_images():
    
    token_key = request.form.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = []

    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 401

    missing_fields = []
    if not request.form.get("image_digest"):
        missing_fields.append("image digest")
    if not request.form.get("image_name"):
        missing_fields.append("image name")

    if missing_fields:
        return jsonify({"error": f"Missing: {', '.join(missing_fields)}"}), 400

    image_digest = request.form.get("image_digest")
    image_name = request.form.get("image_name")

    result, status_code = sign_base_image_digest(audit_trail, image_digest, image_name)

    return jsonify({"message": result, "status": status_code}), status_code

@image_bp.route('/v1/verify-base-image', methods=['POST'])
def verify_base_image():
    
    token_key = request.form.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = []

    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 401

    missing_fields = []
    if not request.form.get("image_digest"):
        missing_fields.append("image digest")
    if not request.form.get("image_name"):
        missing_fields.append("image name")

    if missing_fields:
        return jsonify({"error": f"Missing: {', '.join(missing_fields)}"}), 400

    image_digest = request.form.get("image_digest")
    image_name = request.form.get("image_name")
    
    verify_image_status = verify_base_image_digest(audit_trail, image_digest, image_name)
    return verify_image_status