from flask import Flask, request, jsonify, Response, send_file
import tempfile
import subprocess
import os
import json
from apscheduler.schedulers.background import BackgroundScheduler
import threading
import io
from datetime import datetime
from file_system.File_Handling import save_scan_files
from file_system.PDF_Generator import summary_to_pdf
from file_system.Image_Signature import sign_image_digest, verify_image_digest
from utils.Schedule_Handling import scheduled_event
from utils.JWT_Path import jwt_path_to_resources, decode_jwt_path_to_resources
from file_system.Resource_Handling import get_resources, list_resources
from database.Validate_Token import validate_token
from database.Create_db import create_database
from database.Create_Key import create_key
from database.Key_Status import enable_key, disable_key
from validation.Check_Format import check_json_format
from vuln_scan.Kev_Catalog import compare_kev_catalog
from core.System import install_tools
from core.Variables import version

def threading_save_scan_files(current_repo, sbom_content, sast_report, trivy_report, vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author, timestamp, exclusions_file_content):
    sbom_file_obj = io.BytesIO(sbom_content)
    save_scan_files(current_repo, sbom_file_obj, sast_report, trivy_report, vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author, timestamp, exclusions_file_content)

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

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path_to_resources_token = jwt_path_to_resources(organization ,current_repo, timestamp)

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

    threading.Thread(
        target=threading_save_scan_files,
        args=(current_repo, sbom_content, sast_report_content, trivy_report_content, vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author, timestamp, exclusions_file_content)
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

@app.route('/v1/health-check', methods=['GET'])
def health_check():

    # i plan to have an api key thing here
#    api_key = request.form.get("api-key")
#    if not api_key:
#        return jsonify({"error": "api_key missing"}), 403

    return jsonify({
        "status": "ok",
        "message": "Backend is alive",
        "version": version
    }), 200

@app.route('/v1/get-resources', methods=['GET'])
def get_resource():

    file_name = request.args.getlist('file_name') or None
    
    token_key = request.args.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 400
    
    response, valid_token = validate_token(token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 404
    organization = response

    # i plan to have an api key thing here
#    api_key = request.form.get("api-key")
#    if not api_key:
#        return jsonify({"error": "api_key missing"}), 403

    path_to_resources_token = request.args.get("path_to_resources_token")
    if not path_to_resources_token:
        return jsonify({"error": "path_to_resources_token missing"}), 400
    
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)

    if valid == True:
        files_to_get_and_return = get_resources(organization_decoded, current_repo_decoded, timestamp_decoded, file_name)
        return files_to_get_and_return
    else:
        return jsonify({"error": "invalid jwt token"}), 404
    
@app.route('/v1/list-resources', methods=['GET'])
def list_resource():
    
    token_key = request.args.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 400
    
    response, valid_token = validate_token(token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 404
    organization = response

    # i plan to have an api key thing here
#    api_key = request.form.get("api-key")
#    if not api_key:
#        return jsonify({"error": "api_key missing"}), 403

    path_to_resources_token = request.args.get("path_to_resources_token")
    if not path_to_resources_token:
        return jsonify({"error": "path_to_resources_token missing"}), 400
    
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)

    if valid == True:
        files_to_return_json = list_resources(organization_decoded, current_repo_decoded, timestamp_decoded)
        return files_to_return_json
    else:
        return jsonify({"error": "invalid jwt token"}), 404
    
@app.route('/v1/generate-pdf', methods=['GET'])
def generate_pdf():
    
    token_key = request.args.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 400
    
    response, valid_token = validate_token(token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 404
    organization = response

    # i plan to have an api key thing here
#    api_key = request.form.get("api-key")
#    if not api_key:
#        return jsonify({"error": "api_key missing"}), 403

    path_to_resources_token = request.args.get("path_to_resources_token")
    if not path_to_resources_token:
        return jsonify({"error": "path_to_resources_token missing"}), 400
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)
    
    if valid == True:
        pdf_filename_path = summary_to_pdf(organization_decoded, current_repo_decoded, timestamp_decoded)
        return send_file(pdf_filename_path, mimetype="application/pdf", as_attachment=True) 
    else:
        return jsonify({"error": "invalid jwt token"}), 404

@app.route('/v1/verify-image', methods=['POST'])
def verify_image():
    
    token_key = request.form.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 400
    
    response, valid_token = validate_token(token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 404
    organization = response

    missing_fields = []
    if not request.form.get("image"):
        missing_fields.append("image")
    if not request.form.get("commit_sha"):
        missing_fields.append("commit sha")
    if not request.form.get("commit_author"):
        missing_fields.append("commit author")
    if not request.form.get("path_to_resources_token"):
        missing_fields.append("path to resources token")

    if missing_fields:
        return jsonify({"error": f"Missing: {', '.join(missing_fields)}"}), 400

    image_digest = request.form.get("image")
    commit_sha = request.form.get("commit_sha")
    commit_author = request.form.get("commit_author")
    path_to_resources_token = request.form.get("path_to_resources_token")

    if not path_to_resources_token:
        return jsonify({"error": "path_to_resources_token missing"}), 400
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)
    
    if valid == True:
        verify_image_status = verify_image_digest(image_digest, organization_decoded, current_repo_decoded, timestamp_decoded, commit_sha, commit_author)
        return verify_image_status
    else:
        return jsonify({"error": "invalid jwt token"}), 404

@app.route('/v1/sign-image', methods=['POST'])
def sign_images():
    
    token_key = request.form.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 400
    
    response, valid_token = validate_token(token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 404
    organization = response

    missing_fields = []
    if not request.form.get("image"):
        missing_fields.append("image")
    if not request.form.get("current_repo"):
        missing_fields.append("current repo")
    if not request.form.get("commit_sha"):
        missing_fields.append("commit sha")
    if not request.form.get("commit_author"):
        missing_fields.append("commit author")

    if missing_fields:
        return jsonify({"error": f"Missing: {', '.join(missing_fields)}"}), 400

    image_digest = request.form.get("image")
    current_repo = request.form.get("current_repo")
    commit_sha = request.form.get("commit_sha")
    commit_author = request.form.get("commit_author")

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path_to_resources_token = jwt_path_to_resources(organization ,current_repo, timestamp)

    result_parsed = {
    "path_to_resources_token": path_to_resources_token
    }
    sign_image_digest(image_digest, organization, current_repo, timestamp, commit_sha, commit_author)
    return jsonify(result_parsed)

install_tools()
scheduled_event()
create_database()

scheduler = BackgroundScheduler()
scheduler.add_job(scheduled_event, 'cron', hour=3, minute=0)
scheduler.start()