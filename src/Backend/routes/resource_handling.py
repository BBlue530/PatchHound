from flask import request, jsonify, Blueprint
from utils.jwt_path import decode_jwt_path_to_resources
from file_system.resource_handling import get_resources, list_resources, get_latest_workflow_run
from database.validate_token import validate_token
from logs.event_handler import event
from core.variables import log_type_info, log_type_debug, log_type_error, log_message_key, log_level_key, log_module_key, log_details_key

resource_bp = Blueprint("resource", __name__)

@resource_bp.route('/v1/get-resources', methods=['GET'])
def get_resource():

    file_name = request.args.getlist('file_name') or None
    
    token_key = request.args.get("token")
    if not token_key:
        event(audit_trail, {
            log_message_key: "missing authentication token",
            log_level_key: log_type_info,
            log_module_key: "get_resource",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = False

    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        event(audit_trail, {
            log_message_key: "invalid authentication token",
            log_level_key: log_type_info,
            log_module_key: "get_resource",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": f"{response}"}), 401
    organization = response

    path_to_resources_token = request.args.get("path_to_resources_token")
    if not path_to_resources_token:
        event(audit_trail, {
            log_message_key: "missing path_to_resources_token",
            log_level_key: log_type_info,
            log_module_key: "get_resource",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "path_to_resources_token missing"}), 400
    
    latest_resource = request.args.get("latest_resource")
    if not latest_resource:
        event(audit_trail, {
            log_message_key: "missing latest resource declaration",
            log_level_key: log_type_info,
            log_module_key: "get_resource",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "Latest resource declaration missing"}), 400
    
    repo_resources = request.args.get("repo_resources")
    if not repo_resources:
        event(audit_trail, {
            log_message_key: "missing repo resource declaration",
            log_level_key: log_type_info,
            log_module_key: "get_resource",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "Repo resource declaration missing"}), 400
    
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)

    if latest_resource.lower() == "true":
        timestamp_decoded, valid = get_latest_workflow_run(organization_decoded, current_repo_decoded)
        if valid == False:
            event(audit_trail, {
                log_message_key: "missing scans found for repo",
                log_level_key: log_type_error,
                log_module_key: "get_resource",
                log_details_key: {
                    "client_ip": request.remote_addr,
                    "current_repo_decoded": current_repo_decoded
                }
            })
            return jsonify({"error": "No scans found for repo"}), 404
        
    if repo_resources.lower() == "true":
        timestamp_decoded = ""

    if valid == True:
        files_to_get_and_return = get_resources(organization_decoded, current_repo_decoded, timestamp_decoded, file_name)
        event(audit_trail, {
            log_message_key: "get resources endpoint called",
            log_level_key: log_type_info,
            log_module_key: "get_resource",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return files_to_get_and_return
    
@resource_bp.route('/v1/list-resources', methods=['GET'])
def list_resource():
    
    token_key = request.args.get("token")
    if not token_key:
        event(audit_trail, {
            log_message_key: "missing authentication token",
            log_level_key: log_type_info,
            log_module_key: "list_resource",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = False

    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        event(audit_trail, {
            log_message_key: "invalid authentication token",
            log_level_key: log_type_info,
            log_module_key: "list_resource",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": f"{response}"}), 401
    organization = response

    path_to_resources_token = request.args.get("path_to_resources_token")
    if not path_to_resources_token:
        event(audit_trail, {
            log_message_key: "missing path_to_resources_token",
            log_level_key: log_type_info,
            log_module_key: "list_resource",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "path_to_resources_token missing"}), 400
    
    latest_resource = request.args.get("latest_resource")
    if not latest_resource:
        event(audit_trail, {
            log_message_key: "missing latest_resource declaration",
            log_level_key: log_type_info,
            log_module_key: "list_resource",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "Latest resource declaration missing"}), 400
    
    repo_resources = request.args.get("repo_resources")
    if not repo_resources:
        event(audit_trail, {
            log_message_key: "missing repo_resources declaration",
            log_level_key: log_type_info,
            log_module_key: "list_resource",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "Repo resource declaration missing"}), 400
    
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)

    if latest_resource.lower() == "true":
        timestamp_decoded, valid = get_latest_workflow_run(organization_decoded, current_repo_decoded)
        if valid == False:
            event(audit_trail, {
            log_message_key: "missing scans found for repo",
            log_level_key: log_type_info,
            log_module_key: "list_resource",
            log_details_key: {
                "client_ip": request.remote_addr,
                "current_repo_decoded": current_repo_decoded
            }
        })
            return jsonify({"error": "No scans found for repo"}), 404

    if repo_resources.lower() == "true":
        timestamp_decoded = ""

    if valid == True:
        files_to_return_json = list_resources(organization_decoded, current_repo_decoded, timestamp_decoded)
        event(audit_trail, {
            log_message_key: "list resources endpoint called",
            log_level_key: log_type_info,
            log_module_key: "list_resource",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return files_to_return_json