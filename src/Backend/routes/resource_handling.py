from flask import request, jsonify, Blueprint
from utils.jwt_path import decode_jwt_path_to_resources
from file_system.resource_handling import get_resources, list_resources, get_latest_workflow_run
from database.validate_token import validate_token
from logs.export_logs import log_exporter

resource_bp = Blueprint("resource", __name__)

@resource_bp.route('/v1/get-resources', methods=['GET'])
def get_resource():

    file_name = request.args.getlist('file_name') or None
    
    token_key = request.args.get("token")
    if not token_key:
        new_entry = {
            "message": "Missing authentication token",
            "level": "error",
            "module": "get-resources",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = False

    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        new_entry = {
            "message": "Invalid authentication token",
            "level": "error",
            "module": "get-resources",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": f"{response}"}), 401
    organization = response

    path_to_resources_token = request.args.get("path_to_resources_token")
    if not path_to_resources_token:
        new_entry = {
            "message": "Missing path_to_resources_token",
            "level": "error",
            "module": "get-resources",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "path_to_resources_token missing"}), 400
    
    latest_resource = request.args.get("latest_resource")
    if not latest_resource:
        new_entry = {
            "message": "Missing latest resource declaration",
            "level": "error",
            "module": "get-resources",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "Latest resource declaration missing"}), 400
    
    repo_resources = request.args.get("repo_resources")
    if not repo_resources:
        new_entry = {
            "message": "Missing repo resource declaration",
            "level": "error",
            "module": "get-resources",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "Repo resource declaration missing"}), 400
    
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)

    if latest_resource.lower() == "true":
        timestamp_decoded, valid = get_latest_workflow_run(organization_decoded, current_repo_decoded)
        if valid == False:
            new_entry = {
                "message": f"Missing scans found for repo: {current_repo_decoded}",
                "level": "error",
                "module": "get-resources",
                "client_ip": request.remote_addr,
            }
            log_exporter(new_entry)
            return jsonify({"error": "No scans found for repo"}), 404
        
    if repo_resources.lower() == "true":
        timestamp_decoded = ""

    if valid == True:
        files_to_get_and_return = get_resources(organization_decoded, current_repo_decoded, timestamp_decoded, file_name)
        new_entry = {
            "message": "Get resources endpoint called",
            "level": "info",
            "module": "get-resources",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return files_to_get_and_return
    
@resource_bp.route('/v1/list-resources', methods=['GET'])
def list_resource():
    
    token_key = request.args.get("token")
    if not token_key:
        new_entry = {
            "message": "Missing authentication token",
            "level": "error",
            "module": "list-resources",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = False

    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        new_entry = {
            "message": "Invalid authentication token",
            "level": "error",
            "module": "list-resources",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": f"{response}"}), 401
    organization = response

    path_to_resources_token = request.args.get("path_to_resources_token")
    if not path_to_resources_token:
        new_entry = {
            "message": "Missing path_to_resources_token",
            "level": "error",
            "module": "list-resources",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "path_to_resources_token missing"}), 400
    
    latest_resource = request.args.get("latest_resource")
    if not latest_resource:
        new_entry = {
            "message": "Missing latest_resource declaration",
            "level": "error",
            "module": "list-resources",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "Latest resource declaration missing"}), 400
    
    repo_resources = request.args.get("repo_resources")
    if not repo_resources:
        new_entry = {
            "message": "Missing repo_resources declaration",
            "level": "error",
            "module": "list-resources",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "Repo resource declaration missing"}), 400
    
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)

    if latest_resource.lower() == "true":
        timestamp_decoded, valid = get_latest_workflow_run(organization_decoded, current_repo_decoded)
        if valid == False:
            new_entry = {
                "message": f"Missing scans found for repo: {current_repo_decoded}",
                "level": "error",
                "module": "list-resources",
                "client_ip": request.remote_addr,
            }
            log_exporter(new_entry)
            return jsonify({"error": "No scans found for repo"}), 404

    if repo_resources.lower() == "true":
        timestamp_decoded = ""

    if valid == True:
        files_to_return_json = list_resources(organization_decoded, current_repo_decoded, timestamp_decoded)
        new_entry = {
            "message": "List resources endpoint called",
            "level": "info",
            "module": "list-resources",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return files_to_return_json