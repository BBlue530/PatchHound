from flask import request, jsonify, Blueprint
import os
import json
import hashlib
from database.validate_token import validate_token
from external_storage.external_storage_get import get_resources_external_storage_internal_use
from external_storage.external_storage_send import send_files_to_external_storage
from file_system.file_save import save_file
from file_system.summary_handling.update_summaries import update_repo_summaries
from utils.helpers import load_file_data
from logs.event_handler import event
from core.variables import *

exclusion_bp = Blueprint("exclusion", __name__)

@exclusion_bp.route('/v1/exclusion-get', methods=['GET'])
def exclusion_get():

    token_key = request.args.get("token")
    if not token_key:
        event(audit_trail, {
            log_message_key: "missing authentication token",
            log_level_key: log_type_info,
            log_module_key: "exclusion_get",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = False

    response, valid_token = validate_token(audit_trail, hashlib.sha256(token_key.encode("utf-8")).hexdigest())
    if valid_token == False:
        event(audit_trail, {
            log_message_key: "invalid authentication token",
            log_level_key: log_type_info,
            log_module_key: "exclusion_get",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": f"{response}"}), 401
    organization = response

    repo_name = request.args.get("current_repo")
    if not repo_name:
        event(audit_trail, {
            log_message_key: "missing current_repo",
            log_level_key: log_type_info,
            log_module_key: "exclusion_get",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "current_repo missing"}), 400
    
    repo_dir = os.path.join(all_resources_folder, all_repo_scans_folder, organization, repo_name)
    repo_exclusion_file = f"{repo_name}{exclusions_file_path_ending}"
    repo_exclusion_file_path = os.path.join(repo_dir, repo_exclusion_file)
    
    if os.environ.get("external_storage_enabled", "False").lower() == "true":
        memory_file = get_resources_external_storage_internal_use(repo_exclusion_file_path)
        if memory_file is None:
            event(audit_trail, {
                log_message_key: "missing scan data files from external storage",
                log_level_key: log_type_error,
                log_module_key: "exclusion_get",
                log_details_key: {
                    "client_ip": request.remote_addr,
                    "repo_exclusion_file_path": repo_exclusion_file_path
                }
            })
            return jsonify({"error": "Exclusion file not found"}), 404
        repo_exclusion_file_data = json.load(memory_file)

        if not repo_exclusion_file_data:
            event(audit_trail, {
                log_message_key: "missing exclusion_file from external storage",
                log_level_key: log_type_error,
                log_module_key: "exclusion_get",
                log_details_key: {
                    "client_ip": request.remote_addr,
                    "repo_exclusion_file_path": repo_exclusion_file_path
                }
            })
            return jsonify({"error": "exclusion file missing"}), 404
        
    else:
        if os.path.exists(repo_exclusion_file_path):
            repo_exclusion_file_data = load_file_data(repo_exclusion_file_path)
        else:
            event(audit_trail, {
                log_message_key: "missing exclusion_file from local storage",
                log_level_key: log_type_error,
                log_module_key: "exclusion_get",
                log_details_key: {
                    "client_ip": request.remote_addr,
                    "repo_exclusion_file_path": repo_exclusion_file_path
                }
            })
            return jsonify({"error": "exclusion file missing"}), 404

    event(audit_trail, {
        log_message_key: "exclusion get endpoint called",
        log_level_key: log_type_info,
        log_module_key: "exclusion_get",
        log_details_key: {
            "client_ip": request.remote_addr,
        }
    })

    return repo_exclusion_file_data

@exclusion_bp.route('/v1/exclusion-post', methods=['POST'])
def exclusion_post():

    token_key = request.form.get("token")
    if not token_key:
        event(audit_trail, {
            log_message_key: "missing authentication token",
            log_level_key: log_type_info,
            log_module_key: "exclusion_post",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = []

    response, valid_token = validate_token(audit_trail, hashlib.sha256(token_key.encode("utf-8")).hexdigest())
    if valid_token == False:
        event(audit_trail, {
            log_message_key: "invalid authentication token",
            log_level_key: log_type_info,
            log_module_key: "exclusion_post",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": f"{response}"}), 401
    organization = response

    repo_name = request.form.get("current_repo")
    if not repo_name:
        event(audit_trail, {
            log_message_key: "missing current_repo",
            log_level_key: log_type_info,
            log_module_key: "exclusion_post",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
        return jsonify({"error": "current_repo missing"}), 400
    
    repo_dir = os.path.join(all_resources_folder, all_repo_scans_folder, organization, repo_name)
    repo_exclusion_file_name = f"{repo_name}{exclusions_file_path_ending}"
    repo_exclusion_file_path = os.path.join(repo_dir, repo_exclusion_file_name)

    new_repo_exclusion_file = request.files['new_exclusion_file']
    new_repo_exclusion_file_contents = new_repo_exclusion_file.read().decode('utf-8')
    new_repo_exclusion_file_json = json.loads(new_repo_exclusion_file_contents)


    os.makedirs(repo_dir, exist_ok=True)
        
    save_file(repo_exclusion_file_path, new_repo_exclusion_file_json)
    
    if os.environ.get("external_storage_enabled", "False").lower() == "true":
        send_files_to_external_storage(repo_exclusion_file_path, repo_dir)
        event(audit_trail, {
            log_message_key: "exclusion file updated in s3",
            log_level_key: log_type_info,
            log_module_key: "exclusion_post",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })
    else:
        event(audit_trail, {
            log_message_key: "exclusion file updated in local file system",
            log_level_key: log_type_info,
            log_module_key: "exclusion_post",
            log_details_key: {
                "client_ip": request.remote_addr,
            }
        })

    event(audit_trail, {
        log_message_key: "exclusion post endpoint called",
        log_level_key: log_type_info,
        log_module_key: "exclusion_post",
        log_details_key: {
            "client_ip": request.remote_addr,
        }
    })

    update_repo_summaries(audit_trail, repo_dir, repo_name)

    return jsonify({"info": "exclusion file updated"}), 200