from flask import request, jsonify, Blueprint
from utils.jwt_path import decode_jwt_path_to_resources
from file_system.resource_handling import get_resources, list_resources, get_latest_workflow_run
from database.validate_token import validate_token

resource_bp = Blueprint("resource", __name__)

@resource_bp.route('/v1/get-resources', methods=['GET'])
def get_resource():

    file_name = request.args.getlist('file_name') or None
    
    token_key = request.args.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 401
    
    response, valid_token = validate_token(token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 401
    organization = response

    path_to_resources_token = request.args.get("path_to_resources_token")
    if not path_to_resources_token:
        return jsonify({"error": "path_to_resources_token missing"}), 400
    
    latest_resource = request.args.get("latest_resource")
    if not latest_resource:
        return jsonify({"error": "Latest resource declaration missing"}), 400
    
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)

    if latest_resource.lower() == "true":
        timestamp_decoded, valid = get_latest_workflow_run(organization_decoded, current_repo_decoded)
        if valid == False:
            return jsonify({"error": "No scans found for repo"}), 404

    if valid == True:
        files_to_get_and_return = get_resources(organization_decoded, current_repo_decoded, timestamp_decoded, file_name)
        return files_to_get_and_return
    else:
        return jsonify({"error": "invalid jwt token"}), 404
    
@resource_bp.route('/v1/list-resources', methods=['GET'])
def list_resource():
    
    token_key = request.args.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 401
    
    response, valid_token = validate_token(token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 401
    organization = response

    path_to_resources_token = request.args.get("path_to_resources_token")
    if not path_to_resources_token:
        return jsonify({"error": "path_to_resources_token missing"}), 400
    
    latest_resource = request.args.get("latest_resource")
    if not latest_resource:
        return jsonify({"error": "Latest resource declaration missing"}), 400
    
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)

    if latest_resource.lower() == "true":
        timestamp_decoded, valid = get_latest_workflow_run(organization_decoded, current_repo_decoded)
        if valid == False:
            return jsonify({"error": "No scans found for repo"}), 404

    if valid == True:
        files_to_return_json = list_resources(organization_decoded, current_repo_decoded, timestamp_decoded)
        return files_to_return_json
    else:
        return jsonify({"error": "invalid jwt token"}), 404