from flask import request, jsonify, Blueprint
from datetime import datetime
from file_system.image_signature import sign_image_digest, verify_image_digest
from utils.jwt_path import jwt_path_to_resources, decode_jwt_path_to_resources
from database.validate_token import validate_token

image_bp = Blueprint("image", __name__)

@image_bp.route('/v1/verify-image', methods=['POST'])
def verify_image():
    
    token_key = request.form.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 401
    
    response, valid_token = validate_token(token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 401
    organization = response

    missing_fields = []
    if not request.form.get("image"):
        missing_fields.append("image")
    if not request.form.get("commit_sha"):
        missing_fields.append("commit sha")
    if not request.form.get("commit_author"):
        missing_fields.append("commit author")
    if not request.form.get("path_to_resources_token"):
        missing_fields.append("path to resources token")

    if missing_fields:
        return jsonify({"error": f"Missing: {', '.join(missing_fields)}"}), 400

    image_digest = request.form.get("image")
    commit_sha = request.form.get("commit_sha")
    commit_author = request.form.get("commit_author")
    path_to_resources_token = request.form.get("path_to_resources_token")

    if not path_to_resources_token:
        return jsonify({"error": "path_to_resources_token missing"}), 400
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)
    
    if valid == True:
        verify_image_status = verify_image_digest(image_digest, organization_decoded, current_repo_decoded, timestamp_decoded, commit_sha, commit_author)
        return verify_image_status
    else:
        return jsonify({"error": "invalid jwt token"}), 404

@image_bp.route('/v1/sign-image', methods=['POST'])
def sign_images():
    
    token_key = request.form.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 401
    
    response, valid_token = validate_token(token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 401
    organization = response

    missing_fields = []
    if not request.form.get("image"):
        missing_fields.append("image")
    if not request.form.get("current_repo"):
        missing_fields.append("current repo")
    if not request.form.get("commit_sha"):
        missing_fields.append("commit sha")
    if not request.form.get("commit_author"):
        missing_fields.append("commit author")

    if missing_fields:
        return jsonify({"error": f"Missing: {', '.join(missing_fields)}"}), 400

    image_digest = request.form.get("image")
    current_repo = request.form.get("current_repo")
    commit_sha = request.form.get("commit_sha")
    commit_author = request.form.get("commit_author")

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path_to_resources_token = jwt_path_to_resources(organization ,current_repo, timestamp)

    result_parsed = {
    "path_to_resources_token": path_to_resources_token
    }
    sign_image_digest(image_digest, organization, current_repo, timestamp, commit_sha, commit_author)
    return jsonify(result_parsed)