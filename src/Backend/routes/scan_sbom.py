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
from logs.export_logs import log_exporter
from database.validate_token import validate_token
from vuln_scan.kev_catalog import compare_kev_catalog

scan_sbom_bp = Blueprint("scan_sbom", __name__)

def threading_save_scan_files(audit_trail, current_repo, syft_sbom_content, semgrep_sast_report, trivy_report, grype_vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author, tool_versions, scan_root, timestamp, exclusions_file_content, semgrep_sast_ruleset, fail_on_severity):
    syft_sbom_file_obj = io.BytesIO(syft_sbom_content)
    save_scan_files(audit_trail, current_repo, syft_sbom_file_obj, semgrep_sast_report, trivy_report, grype_vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author, tool_versions, scan_root, timestamp, exclusions_file_content, semgrep_sast_ruleset, fail_on_severity)

@scan_sbom_bp.route('/v1/scan-sbom', methods=['POST'])
def scan_sbom():
    
    token_key = request.form.get("token")
    if not token_key:
        new_entry = {
            "message": "Missing authentication token",
            "level": "error",
            "module": "scan-sbom",
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
            "module": "scan-sbom",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
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
    if not request.form.get("tool_versions"):
        missing_fields.append("tool versions")
    if not request.form.get("scan_root"):
        missing_fields.append("scan root")

    if missing_fields:
        new_entry = {
            "message": f"Missing fields: {missing_fields}",
            "level": "error",
            "module": "scan-sbom",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": f"Missing: {', '.join(missing_fields)}"}), 400

    syft_sbom_file = request.files['sbom']
    semgrep_sast_report = request.files['sast_report']
    semgrep_sast_ruleset_str = request.form.get("sast_ruleset")
    trivy_report = request.files['trivy_report']
    exclusions_file = request.files['exclusions']
    current_repo = request.form.get("current_repo")
    commit_sha = request.form.get("commit_sha")
    commit_author = request.form.get("commit_author")
    tool_versions_str = request.form.get("tool_versions")
    scan_root_str = request.form.get("scan_root")
    alert_system_webhook = request.form.get("alert_system_webhook")
    fail_on_severity = request.form.get("fail_on_severity")

    try:
        scan_root_data = json.loads(scan_root_str)
    except (json.JSONDecodeError, TypeError):
        scan_root_data = {}
    scan_root = scan_root_data["scan_root"]

    try:
        tool_versions = json.loads(tool_versions_str)
    except (json.JSONDecodeError, TypeError):
        tool_versions = {}

    try:
        semgrep_sast_ruleset = json.loads(semgrep_sast_ruleset_str)
    except (json.JSONDecodeError, TypeError):
        semgrep_sast_ruleset_str = {}
    
    try:
        syft_sbom_file.seek(0)
        json.load(syft_sbom_file)
        syft_sbom_file.seek(0)
    except json.JSONDecodeError:
        new_entry = {
            "message": "SBOM file not valid json",
            "level": "error",
            "module": "scan-sbom",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "SBOM file must be valid JSON"}), 400
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        syft_sbom_file.save(tmp)
        tmp_path = tmp.name

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    audit_trail_event(audit_trail, "SCAN_START", {
        "timestamp_id": timestamp,
        "repo": current_repo,
        "commit_sha": commit_sha,
        "commit_author": commit_author
    })

    try:
        grype_vulns_cyclonedx_json = subprocess.run(
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
        new_entry = {
            "message": f"Grype scan failed. stderr: {e.stderr} stdout: {e.stdout} return_code: {e.returncode} cmd: {e.cmd}",
            "level": "error",
            "module": "scan-sbom",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "Grype scan failed", "stderr": e.stderr, "stdout": e.stdout, "return_code": e.returncode, "cmd": e.cmd}), 500
    finally:
        os.unlink(tmp_path)
    
    grype_vulns_cyclonedx_json_data = json.loads(grype_vulns_cyclonedx_json.stdout)

    try:
        trivy_report.seek(0)
        trivy_report_data = json.load(trivy_report)
        trivy_report.seek(0)
    except json.JSONDecodeError:
        new_entry = {
            "message": "Trivy scan is not valid json",
            "level": "error",
            "module": "scan-sbom",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        return jsonify({"error": "Trivy report is not valid JSON"}), 400
    
    prio_vuln_data = compare_kev_catalog(audit_trail, grype_vulns_cyclonedx_json_data, trivy_report_data)

    path_to_resources_token = jwt_path_to_resources(audit_trail, organization ,current_repo, timestamp)

    result_parsed = {
    "vulns_cyclonedx_json": grype_vulns_cyclonedx_json_data,
    "prio_vulns": prio_vuln_data,
    "path_to_resources_token": path_to_resources_token
    }

    syft_sbom_file.seek(0)
    syft_sbom_content = syft_sbom_file.read()
    semgrep_sast_report.seek(0)
    semgrep_sast_report_content = semgrep_sast_report.read()
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
        args=(audit_trail, current_repo, syft_sbom_content, semgrep_sast_report_content, trivy_report_content, grype_vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author, tool_versions, scan_root, timestamp, exclusions_file_content, semgrep_sast_ruleset, fail_on_severity)
    ).start()

    new_entry = {
        "message": "Scan SBOM endpoint called",
        "level": "info",
        "module": "scan-sbom",
        "client_ip": request.remote_addr,
    }
    log_exporter(new_entry)
    return jsonify(result_parsed)