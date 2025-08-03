from flask import Flask, request, jsonify, Response, send_file
import tempfile
import subprocess
import os
import json
from apscheduler.schedulers.background import BackgroundScheduler
import threading
import io
from validation.File_Handling import save_scan_files
from utils.Schedule_Handling import scheduled_event
from database.Validate_Token import validate_token
from database.Create_db import create_database
from database.Create_Key import create_key
from database.Key_Status import enable_key, disable_key
from validation.Check_Format import check_json_format
from vuln_scan.Kev_Catalog import compare_kev_catalog
from core.System import install_tools
from core.Variables import version

def threading_save_scan_files(current_repo, sbom_content, sast_report, trivy_report, vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author):
    sbom_file_obj = io.BytesIO(sbom_content)
    save_scan_files(current_repo, sbom_file_obj, sast_report, trivy_report, vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author)

app = Flask(__name__)
# Dont think i need this anymore but scared to remove it for now since its working like it should
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

@app.route('/v1/scan-sbom', methods=['POST'])
def scan_sbom():
    
    token_key = request.form.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 400
    
    response, valid_token = validate_token(token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 404
    organization = response

    missing_fields = []
    if 'sbom' not in request.files:
        missing_fields.append("SBOM file")
    if not request.form.get("sast_report"):
        missing_fields.append("sast report")
    if not request.form.get("current_repo"):
        missing_fields.append("current repo")
    if not request.form.get("commit_sha"):
        missing_fields.append("commit sha")
    if not request.form.get("commit_author"):
        missing_fields.append("commit author")
    if not request.form.get("trivy_report"):
        missing_fields.append("trivy report")

    if missing_fields:
        return jsonify({"error": f"Missing: {', '.join(missing_fields)}"}), 400

    sbom_file = request.files['sbom']
    sast_report = request.files['sast_report']
    trivy_report = request.files['trivy_report']
    current_repo = request.form.get("current_repo")
    commit_sha = request.form.get("commit_sha")
    commit_author = request.form.get("commit_author")
    alert_system_webhook = request.form.get("alert_system_webhook")

    is_cyclonedx = check_json_format(sbom_file)
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

    try:
        vulns_cyclonedx_json = subprocess.run(
        ["grype", f"sbom:{tmp_path}", "-o", "cyclonedx-json"],
        capture_output=True,
        text=True,
        check=True
        )

    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Grype scan failed", "details": e.stderr}), 500
    finally:
        os.unlink(tmp_path)
    
    vulns_cyclonedx_json_data = json.loads(vulns_cyclonedx_json.stdout)
    prio_vuln_data = compare_kev_catalog(vulns_cyclonedx_json_data)

    result_parsed = {
    "vulns_cyclonedx_json": vulns_cyclonedx_json_data,
    "prio_vulns": prio_vuln_data
    }

    sbom_file.seek(0)
    sbom_content = sbom_file.read()

    threading.Thread(
        target=threading_save_scan_files,
        args=(current_repo, sbom_content, sast_report, trivy_report, vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author)
    ).start()
    return jsonify(result_parsed)

@app.route('/v1/create-token-key', methods=['POST'])
def create_token_key():

    organization = request.form.get("organization")
    if not organization:
        return jsonify({"error": "organization missing"}), 400
    
    expiration_days = request.form.get("expiration_days")
    if not expiration_days:
        return jsonify({"error": "expiration_days missing"}), 400
    try:
        expiration_days = int(expiration_days)
    except ValueError:
        return jsonify({"error": "expiration_days must be an integer"}), 400
    
    # i plan to have an api key thing here
#    api_key = request.form.get("api-key")
#    if not api_key:
#        return jsonify({"error": "api_key missing"}), 403

    response = create_key(organization, expiration_days)
    return response

@app.route('/v1/change-key-status', methods=['POST'])
def change_token_key_status():

    token_key = request.form.get("token")
    if not token_key:
        return jsonify({"error": "token key missing"}), 400
    
    instructions = request.form.get("instructions")
    if not instructions:
        return jsonify({"error": "instructions missing"}), 400
    
    # i plan to have an api key thing here
#    api_key = request.form.get("api-key")
#    if not api_key:
#        return jsonify({"error": "api_key missing"}), 403

    if instructions == "enable":
        response = enable_key(token_key)
        return response
    
    elif instructions == "disable":
        response = disable_key(token_key)
        return response

@app.route('/v1/healthcheck', methods=['GET'])
def healthcheck():
    return jsonify({
        "status": "ok",
        "message": "Backend is alive",
        "version": version
    }), 200

install_tools()
scheduled_event()
create_database()

scheduler = BackgroundScheduler()
scheduler.add_job(scheduled_event, 'cron', hour=3, minute=0)
scheduler.start()