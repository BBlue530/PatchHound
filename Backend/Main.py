from flask import Flask, request, jsonify, Response
import tempfile
import subprocess
import os
import json
from apscheduler.schedulers.background import BackgroundScheduler
import datetime
from File_Handling import save_scan_files
from Vulnerability_DB import update_grype_kev_db
from License_Handling import validate_license
from Check_Format import check_json_format
from Kev_Catalog import compare_kev_catalog
from System import install_tools

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
    
    sbom_file = request.files['sbom']
    if 'sbom' not in request.files:
        return jsonify({"error": "No SBOM file uploaded"}), 400
    
    current_repo = request.form.get("current_repo")
    if not current_repo:
        return jsonify({"error": "No current repo detected"}), 400

    commit_sha = request.form.get("commit_sha")
    if not commit_sha:
        return jsonify({"error": "No commit sha detected"}), 400

    commit_author = request.form.get("commit_author")
    if not commit_author:
        return jsonify({"error": "No commit author detected"}), 400
    
    # Get both the alert system its going to use and the webhook
    alert_system = request.form.get("alert_system")
    alert_system_webhook = request.form.get("alert_system_webhook")

    is_cyclonedx = check_json_format(sbom_file)
    if is_cyclonedx == False:
        return jsonify({"error": "SBOM file must be valid JSON format CycloneDX 1.6"}), 400
    
    try:
        sbom_file.seek(0)
        json.load(sbom_file)
        sbom_file.seek(0)  # Reset file pointer if needed
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

    save_scan_files(current_repo, sbom_file, vulns_cyclonedx_json_data, prio_vuln_data, license_key, alert_system, alert_system_webhook, commit_sha, commit_author)

    return jsonify(result_parsed)

if __name__ == "__main__":
    install_tools()
    update_grype_kev_db()
    scheduler = BackgroundScheduler()
    scheduler.add_job(update_grype_kev_db, 'cron', hour=3, minute=0)
    scheduler.start()
    app.run(host="0.0.0.0", port=8080)
