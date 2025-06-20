from flask import Flask, request, jsonify
import tempfile
import subprocess
import os
import json
import requests

app = Flask(__name__)

@app.route('/scan-sbom', methods=['POST'])
def scan_sbom():
    
    license_key = request.form.get("license")
    if not license_key:
        return jsonify({"error": "License key missing"}), 400
    valid_license = validate_license(license_key)
    if valid_license == False:
        return jsonify({"error": "Invalid license"}), 404

def validate_license(license_key):
    url = "https://u1e8fkkqcl.execute-api.eu-north-1.amazonaws.com/v1/CheckKey"
    headers = {"Content-Type": "application/json"}

    data = {
        "LicenseKey": license_key
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))

        if response.status_code == 200:
            print("License = valid")
            return True
        else:
            print(f"License validation failed: {response.json().get('message', 'Unknown error')}")
            return False

    except Exception as e:
        print(f"Error: {e}")

    if 'sbom' not in request.files:
        return jsonify({"error": "No SBOM file uploaded"}), 400
    
    sbom_file = request.files['sbom']
    if sbom_file.content_type != 'application/json':
        return jsonify({"error": "SBOM file must be JSON"}), 400
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        sbom_file.save(tmp)
        tmp_path = tmp.name

    try:
        # Run grype scan on SBOM
        result = subprocess.run(
            ["grype", f"sbom:{tmp_path}", "-o", "json"],
            capture_output=True,
            text=True,
            check=True
        )
        vulns_json = json.loads(result.stdout)

        # Count severities
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Unknown": 0
        }

        for match in vulns_json.get("matches", []):
            sev = match.get("vulnerability", {}).get("severity", "Unknown")
            if sev not in severity_counts:
                severity_counts[sev] = 0
            severity_counts[sev] += 1

    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Grype scan failed", "details": e.stderr}), 500
    finally:
        os.unlink(tmp_path)  # Clean up temp file
    
    return jsonify({
        "severity_counts": severity_counts,
        "vulnerabilities": vulns_json
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
