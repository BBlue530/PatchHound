from flask import request, jsonify, Blueprint
import tempfile
import subprocess
import os
import json
import threading
import io
from datetime import datetime
from file_system.file_handling import save_scan_files
from utils.jwt_path import jwt_path_to_resources
from logs.audit_trail import audit_trail_event
from database.validate_token import validate_token
from validation.check_format import check_json_format
from vuln_scan.kev_catalog import compare_kev_catalog

scan_sbom_bp = Blueprint("scan_sbom", __name__)

def threading_save_scan_files(audit_trail, current_repo, sbom_content, sast_report, trivy_report, vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author, timestamp, exclusions_file_content):
    sbom_file_obj = io.BytesIO(sbom_content)
    save_scan_files(audit_trail, current_repo, sbom_file_obj, sast_report, trivy_report, vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author, timestamp, exclusions_file_content)

@scan_sbom_bp.route('/v1/scan-sbom', methods=['POST'])
def scan_sbom():
    
    token_key = request.form.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = []
    
    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 401
    organization = response

    missing_fields = []
    if 'sbom' not in request.files:
        missing_fields.append("SBOM file")
    if 'sast_report' not in request.files:
        missing_fields.append("sast report")
    if 'trivy_report' not in request.files:
        missing_fields.append("trivy report")
    if 'exclusions' not in request.files:
        missing_fields.append("exclusions file")
    if not request.form.get("current_repo"):
        missing_fields.append("current repo")
    if not request.form.get("commit_sha"):
        missing_fields.append("commit sha")
    if not request.form.get("commit_author"):
        missing_fields.append("commit author")

    if missing_fields:
        return jsonify({"error": f"Missing: {', '.join(missing_fields)}"}), 400

    sbom_file = request.files['sbom']
    sast_report = request.files['sast_report']
    trivy_report = request.files['trivy_report']
    exclusions_file = request.files['exclusions']
    current_repo = request.form.get("current_repo")
    commit_sha = request.form.get("commit_sha")
    commit_author = request.form.get("commit_author")
    alert_system_webhook = request.form.get("alert_system_webhook")

    is_cyclonedx = check_json_format(audit_trail, sbom_file)
    if is_cyclonedx == False:
        return jsonify({"error": "SBOM file must be valid JSON format CycloneDX 1.6"}), 400
    
    try:
        sbom_file.seek(0)
        json.load(sbom_file)
        sbom_file.seek(0)
    except json.JSONDecodeError:
        return jsonify({"error": "SBOM file must be valid JSON"}), 400
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        sbom_file.save(tmp)
        tmp_path = tmp.name

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    audit_trail_event(audit_trail, "SCAN_START", {
        "timestamp_id": timestamp,
        "repo": current_repo,
        "commit_sha": commit_sha,
        "commit_author": commit_author
    })

    try:
        vulns_cyclonedx_json = subprocess.run(
        ["grype", f"sbom:{tmp_path}", "-o", "cyclonedx-json"],
        capture_output=True,
        text=True,
        check=True
        )
        audit_trail_event(audit_trail, "GRYPE_SCAN", {
            "status": "success",
            "output_format": "cyclonedx"
        })

    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Grype scan failed", "details": e.stderr}), 500
    finally:
        os.unlink(tmp_path)
    
    vulns_cyclonedx_json_data = json.loads(vulns_cyclonedx_json.stdout)
    prio_vuln_data = compare_kev_catalog(audit_trail, vulns_cyclonedx_json_data)

    path_to_resources_token = jwt_path_to_resources(audit_trail, organization ,current_repo, timestamp)

    result_parsed = {
    "vulns_cyclonedx_json": vulns_cyclonedx_json_data,
    "prio_vulns": prio_vuln_data,
    "path_to_resources_token": path_to_resources_token
    }

    sbom_file.seek(0)
    sbom_content = sbom_file.read()
    sast_report.seek(0)
    sast_report_content = sast_report.read()
    trivy_report.seek(0)
    trivy_report_content = trivy_report.read()
    exclusions_file.seek(0)
    exclusions_file_content = exclusions_file.read()

    audit_trail_event(audit_trail, "RETURN_FILE_TO_CLIENT", {
        "returned": ["vulns_cyclonedx_json", "prio_vulns", "path_to_resources_token"],
        "client": request.remote_addr
    })

    threading.Thread(
        target=threading_save_scan_files,
        args=(audit_trail, current_repo, sbom_content, sast_report_content, trivy_report_content, vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author, timestamp, exclusions_file_content)
    ).start()
    return jsonify(result_parsed)