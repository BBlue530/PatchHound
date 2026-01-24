from flask import request, jsonify, Blueprint
import os
import json
from database.validate_token import validate_token
from external_storage.external_storage_get import get_resources_external_storage_internal_use
from external_storage.external_storage_send import send_files_to_external_storage
from file_system.file_save import save_file
from file_system.summary_handling.update_summaries import update_repo_summaries
from utils.helpers import load_file_data
from logs.export_logs import log_exporter
from core.variables import *

exclusion_bp = Blueprint("exclusion", __name__)

@exclusion_bp.route('/v1/exclusion-get', methods=['GET'])
def exclusion_get():

    token_key = request.args.get("token")
    if not token_key:
        new_entry = {
            "message": "Missing authentication token",
            "level": "error",
            "module": "exclusion-get",
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
            "module": "exclusion-get",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": f"{response}"}), 401
    organization = response

    repo_name = request.args.get("current_repo")
    if not repo_name:
        new_entry = {
            "message": "Missing current_repo",
            "level": "error",
            "module": "exclusion-get",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "current_repo missing"}), 400
    
    repo_dir = os.path.join(all_resources_folder, all_repo_scans_folder, organization, repo_name)
    repo_exclusion_file = f"{repo_name}{exclusions_file_path_ending}"
    repo_exclusion_file_path = os.path.join(repo_dir, repo_exclusion_file)
    
    if os.environ.get("external_storage_enabled", "False").lower() == "true":
        memory_file = get_resources_external_storage_internal_use(repo_exclusion_file_path)
        if memory_file is None:
            return jsonify({"error": "Exclusion file not found"}), 404
        repo_exclusion_file_data = json.load(memory_file)

        if not repo_exclusion_file_data:
            new_entry = {
                "message": f"Missing exclusion file [{repo_exclusion_file_path}]",
                "level": "error",
                "module": "exclusion-get",
                "client_ip": request.remote_addr,
            }
            log_exporter(new_entry)
            return jsonify({"error": "exclusion file missing"}), 404
        
    else:
        if os.path.exists(repo_exclusion_file_path):
            repo_exclusion_file_data = load_file_data(repo_exclusion_file_path)
        else:
            new_entry = {
                "message": f"Missing exclusion file [{repo_exclusion_file_path}]",
                "level": "error",
                "module": "exclusion-get",
                "client_ip": request.remote_addr,
            }
            log_exporter(new_entry)
            return jsonify({"error": "exclusion file missing"}), 404
    
    new_entry = {
        "message": "Exclusion get endpoint called",
        "level": "info",
        "module": "exclusion-get",
        "client_ip": request.remote_addr,
    }
    log_exporter(new_entry)

    return repo_exclusion_file_data

@exclusion_bp.route('/v1/exclusion-post', methods=['POST'])
def exclusion_post():

    token_key = request.form.get("token")
    if not token_key:
        new_entry = {
            "message": "Missing authentication token",
            "level": "error",
            "module": "exclusion-post",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = []

    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        new_entry = {
            "message": "Invalid authentication token",
            "level": "error",
            "module": "exclusion-post",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": f"{response}"}), 401
    organization = response

    repo_name = request.form.get("current_repo")
    if not repo_name:
        new_entry = {
            "message": "Missing current_repo",
            "level": "error",
            "module": "exclusion-post",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
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

        new_entry = {
            "message": "Exclusion file updated in s3",
            "level": "info",
            "module": "exclusion-post",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
    else:
        new_entry = {
            "message": "Exclusion file updated in local file system",
            "level": "info",
            "module": "exclusion-post",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)

    
    new_entry = {
        "message": "Exclusion post endpoint called",
        "level": "info",
        "module": "exclusion-post",
        "client_ip": request.remote_addr,
    }
    log_exporter(new_entry)

    update_repo_summaries(audit_trail, repo_dir, repo_name)

    return jsonify({"info": "exclusion file updated"}), 200