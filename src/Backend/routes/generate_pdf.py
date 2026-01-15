from flask import request, jsonify, send_file, Blueprint
import os
import io
import zipfile
import time
from file_system.pdf_report.pdf_generator import summary_to_pdf
from utils.jwt_path import decode_jwt_path_to_resources
from database.validate_token import validate_token
from utils.file_hash import hash_file
from file_system.file_save import sign_file
from logs.export_logs import log_exporter
from core.variables import *

pdf_bp = Blueprint("pdf", __name__)

@pdf_bp.route('/v1/generate-pdf', methods=['GET'])
def generate_pdf():
    
    token_key = request.args.get("token")
    if not token_key:
        new_entry = {
            "message": "Missing authentication token",
            "level": "error",
            "module": "generate-pdf",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = False

    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 401
    organization = response

    path_to_resources_token = request.args.get("path_to_resources_token")
    if not path_to_resources_token:
        new_entry = {
            "message": "Missing path_to_resources_token",
            "level": "error",
            "module": "generate-pdf",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "path_to_resources_token missing"}), 404
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)
    
    if valid == True:
        scan_dir = os.path.join(all_resources_folder, all_repo_scans_folder, organization_decoded, current_repo_decoded, timestamp_decoded)

        cosign_key_path = os.path.join(scan_dir, f"{current_repo_decoded}{cosign_key_path_ending}")
        cosign_pub_path = os.path.join(scan_dir, f"{current_repo_decoded}{cosign_pub_path_ending}")
        
        pdf_filename_path = summary_to_pdf(organization_decoded, current_repo_decoded, timestamp_decoded)

        pdf_sig_path = f"{pdf_filename_path}{sig_path_ending}"

        sign_file(cosign_key_path, cosign_pub_path, pdf_sig_path, pdf_filename_path, current_repo_decoded, scan_dir)

        pdf_report_hash = hash_file(pdf_filename_path)

        for f in [pdf_filename_path, pdf_sig_path, cosign_pub_path]:
            if not os.path.isfile(f):
                time.sleep(0.1)
            if not os.path.isfile(f):
                print(f"[!] {f} does not exist")

        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w') as zf:
            zf.write(pdf_sig_path, arcname=os.path.basename(pdf_sig_path))
            zf.write(cosign_pub_path, arcname=os.path.basename(cosign_pub_path))
            zf.write(pdf_filename_path, arcname=os.path.basename(pdf_filename_path))
            zf.writestr(f"{current_repo_decoded}_pdf{digest_path_ending}", f"SHA256: {pdf_report_hash}")
        memory_file.seek(0)

        new_entry = {
            "message": f"Generate pdf endpoint called path_to_resources_token: {path_to_resources_token}",
            "level": "info",
            "module": "generate-pdf",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)

        return send_file(memory_file, download_name='pdf_report_bundle.zip', as_attachment=True)
    else:
        new_entry = {
            "message": f"Invalid path_to_resources_token: {path_to_resources_token}",
            "level": "error",
            "module": "generate-pdf",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "invalid jwt token"}), 404