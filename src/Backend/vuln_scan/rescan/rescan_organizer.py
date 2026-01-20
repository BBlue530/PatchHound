import os
from datetime import datetime
import shutil
from core.variables import *
from logs.audit_trail import save_audit_trail
from logs.export_logs import log_exporter
from external_storage.external_storage_get import get_resources_external_storage_internal_use_tmp
from external_storage.external_storage_send import send_files_to_external_storage
from vuln_scan.rescan.rescan_scan_data import rescan_scan_data

def rescan_latest_scan_data():
    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")

    temp_resources_root = None
    audit_trail = []
    try:
        if os.environ.get("external_storage_enabled", "False").lower() == "true":
            temp_resources_root = get_resources_external_storage_internal_use_tmp(all_resources_folder)

            repo_scans_dir = os.path.join(temp_resources_root, all_repo_scans_folder)
            image_sign_dir = os.path.join(temp_resources_root, all_image_signature_folder)

            if not os.path.isdir(repo_scans_dir):
                print(f"[!] AWS s3 missing resource file: {temp_resources_root}")
                return
        else:
            repo_scans_dir = os.path.join(all_resources_folder, all_repo_scans_folder)
            image_sign_dir = os.path.join(all_resources_folder, all_image_signature_folder)

            if not os.path.isdir(repo_scans_dir):
                print(f"[~] Creating missing scans folder: {repo_scans_dir}")
                os.makedirs(repo_scans_dir, exist_ok=True)

            if not os.path.isdir(image_sign_dir):
                print(f"[~] Creating missing scans folder: {image_sign_dir}")
                os.makedirs(image_sign_dir, exist_ok=True)
        
        # List all directories inside repo_scans_dir aka the token keys

        for organization in os.listdir(repo_scans_dir):
            token_path = os.path.join(repo_scans_dir, organization)
            if not os.path.isdir(token_path):
                continue
            print(f"[~] Scanning for token key: {organization}")

            # List all directories inside the token key dir which will be the repo_name
            daily_scan = True

            for repo_name in os.listdir(token_path):
                repo_path = os.path.join(token_path, repo_name)
                if not os.path.isdir(repo_path):
                    continue

                # List all directories inside the repo_name dir and sort them.
                # Latest is the first since timestamp sort themself
                timestamp_folders = sorted([f for f in os.listdir(repo_path) if os.path.isdir(os.path.join(repo_path, f))],reverse=True)

                if not timestamp_folders:
                    print(f"[!] No scans found for repo: {repo_name}")
                    new_entry = {
                        "message": f"No scans found for repo: {repo_name}",
                        "level": "error",
                        "module": "scheduled_rescan",
                    }
                    log_exporter(new_entry)
                    continue
                
                timestamp_folder = timestamp_folders[0]
                
                # Create the full path for the latest scan inside the repo
                # repo_scans_dir, organization, repo_name, timestamp_folders, {repo_name}{syft_sbom_path_ending}

                s3_bucker_dir_timestamp_folder = os.path.join(all_resources_folder, all_repo_scans_folder, organization, repo_name, timestamp_folder)

                daily_scan = rescan_scan_data(audit_trail, repo_path, timestamp_folder, repo_name, organization)

                if daily_scan is False:
                    latest_scan_dir = os.path.join(repo_path, timestamp_folder)
                    audit_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                    audit_trail_path = os.path.join(latest_scan_dir, f"{repo_name}_audit_trail_{audit_timestamp}.json")
                    save_audit_trail(audit_trail_path, audit_trail)

                    if os.environ.get("external_storage_enabled", "False").lower() == "true":
                        send_files_to_external_storage(audit_trail_path, s3_bucker_dir_timestamp_folder)

                new_entry = {
                    "message": f"Scan finished for repo: {repo_name} Timestamp: {timestamp_folder}",
                    "level": "error",
                    "module": "scheduled_rescan",
                }
                log_exporter(new_entry)
                print(f"[+] Scan finished for repo: {repo_name}")
                
    finally:
        if temp_resources_root:
            shutil.rmtree(temp_resources_root, ignore_errors=True)