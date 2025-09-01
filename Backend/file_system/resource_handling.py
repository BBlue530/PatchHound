import os
import io
import zipfile
from flask import send_file, abort
from core.variables import all_repo_scans_folder, all_resources_folder

def list_resources(organization_decoded, current_repo_decoded, timestamp_decoded):
    base_dir = os.path.join(all_resources_folder, all_repo_scans_folder, organization_decoded, current_repo_decoded, timestamp_decoded)

    if not os.path.isdir(base_dir):
        abort(404, description=f"Directory not found: {base_dir}")
    
    files_to_return = [
        f
        for f in os.listdir(base_dir)
        if os.path.isfile(os.path.join(base_dir, f))
    ]

    if not files_to_return:
        abort(404, description="No files found to return")

    files_to_return_json = {
    "files": files_to_return
    }
    return files_to_return_json

def get_resources(organization_decoded, current_repo_decoded, timestamp_decoded, file_names):
    base_dir = os.path.join(all_resources_folder, all_repo_scans_folder, organization_decoded, current_repo_decoded, timestamp_decoded)

    if not os.path.isdir(base_dir):
        abort(404, description=f"Directory not found: {base_dir}")
    
    if file_names is None:
        files_to_return = [
            os.path.join(base_dir, f)
            for f in os.listdir(base_dir)
            if os.path.isfile(os.path.join(base_dir, f))
        ]
    else:
        if isinstance(file_names, str):
            file_names = [file_names]

        files_to_return = []
        for fname in file_names:
            if os.path.isdir(fname):
                continue
            full_path = os.path.join(base_dir, fname)
            if os.path.isfile(full_path):
                files_to_return.append(full_path)
            else:
                print(f"requested file not found: {full_path}")

    if not files_to_return:
        abort(404, description="No files found to return")

    if len(files_to_return) == 1:
        return send_file(files_to_return[0], as_attachment=True)

    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w') as zf:
        for filepath in files_to_return:
            zf.write(filepath, arcname=os.path.basename(filepath))
    memory_file.seek(0)
    files_to_get_and_return = send_file(memory_file, download_name='resources.zip', as_attachment=True)
    return files_to_get_and_return

def get_latest_workflow_run(organization, current_repo):
    repo_path = os.path.join(all_resources_folder, all_repo_scans_folder, organization, current_repo)
    timestamp_folders = sorted([f for f in os.listdir(repo_path) if os.path.isdir(os.path.join(repo_path, f))],reverse=True)

    if not timestamp_folders:
        print(f"[!] No scans found for repo: {current_repo}")
        valid = False
        return None, valid
    else:
        valid = True
        return timestamp_folders[0], valid