from flask import Flask, request, jsonify, Response
import tempfile
import subprocess
import os
import json
from Grype_Handling import clear_and_update_grype_cache
from License_Handling import validate_license

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

    if 'sbom' not in request.files:
        return jsonify({"error": "No SBOM file uploaded"}), 400
    
    sbom_file = request.files['sbom']
    try:
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

    result_parsed = {
    "vulns_cyclonedx_json": json.loads(vulns_cyclonedx_json.stdout)
    }

    return jsonify(result_parsed)

if __name__ == "__main__":
    clear_and_update_grype_cache()
    app.run(host="0.0.0.0", port=8080)
