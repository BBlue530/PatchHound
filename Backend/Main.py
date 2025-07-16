from flask import Flask, request, jsonify, Response
import tempfile
import subprocess
import os
import json
from apscheduler.schedulers.background import BackgroundScheduler
import threading
import io
from File_Save import save_scan_files
from Schedule_Handling import scheduled_event
from License_Handling import validate_license
from Check_Format import check_json_format
from Kev_Catalog import compare_kev_catalog
from System import install_tools

def threading_save_scan_files(current_repo, sbom_content, vulns_cyclonedx_json_data, prio_vuln_data, license_key, alert_system_webhook, commit_sha, commit_author):
    sbom_file_obj = io.BytesIO(sbom_content)
    save_scan_files(current_repo, sbom_file_obj, vulns_cyclonedx_json_data, prio_vuln_data, license_key, alert_system_webhook, commit_sha, commit_author)

app = Flask(__name__)
# Dont think i need this anymore but scared to remove it for now since its working like it should
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

@app.route('/v1/scan-sbom', methods=['POST'])
def scan_sbom():
    
    license_key = request.form.get("license")
    if not license_key:
        return jsonify({"error": "License key missing"}), 400
    
    response, valid_license = validate_license(license_key)
    if valid_license == False:
        return jsonify({"error": f"{response}"}), 404
        
    missing_fields = []
    if 'sbom' not in request.files:
        missing_fields.append("SBOM file")
    if not request.form.get("current_repo"):
        missing_fields.append("current repo")
    if not request.form.get("commit_sha"):
        missing_fields.append("commit sha")
    if not request.form.get("commit_author"):
        missing_fields.append("commit author")

    if missing_fields:
        return jsonify({"error": f"Missing: {', '.join(missing_fields)}"}), 400

    sbom_file = request.files['sbom']
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
        args=(current_repo, sbom_content, vulns_cyclonedx_json_data, prio_vuln_data, license_key, alert_system_webhook, commit_sha, commit_author)
    ).start()
    return jsonify(result_parsed)

if __name__ == "__main__":
    install_tools()
    scheduled_event()
    scheduler = BackgroundScheduler()
    scheduler.add_job(scheduled_event, 'cron', hour=3, minute=0)
    scheduler.start()
    app.run(host="0.0.0.0", port=8080)
