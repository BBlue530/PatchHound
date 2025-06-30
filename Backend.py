from flask import Flask, request, jsonify, Response
import tempfile
import subprocess
import os
import json
import requests
import shutil
from pathlib import Path

app = Flask(__name__)
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

def validate_license(license_key):
    url = "https://u1e8fkkqcl.execute-api.eu-north-1.amazonaws.com/v1/CheckKey"
    headers = {"Content-Type": "application/json"}

    data = {
        "LicenseKey": license_key
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))

        if response.status_code == 200:
            message = response.json().get('message', 'Unknown success message')
            print("License = valid")
            return f"License validation: {message}", True
        else:
            message = response.json().get('message', 'Unknown error')
            print(f"License validation failed: {message}")
            return f"License validation: {message}", False

    except Exception as e:
        print(f"Error: {e}")
        return f"License validation error: {str(e)}", False

def clear_grype_cache():
    cache_path = Path.home() / ".cache" / "grype"
    if cache_path.exists():
        print("[~] Clearing Grype cache directory...")
        try:
            shutil.rmtree(cache_path, ignore_errors=True)
            print("[✓] Grype cache cleared.")
        except Exception as e:
            print(f"[!] Failed to clear cache: {e}")
    else:
        print("[!] Grype cache directory does not exist.")

if __name__ == "__main__":
    clear_grype_cache()
    print("[~] Warming up grype DB (may take a few seconds)...")
    try:
        subprocess.run(["grype", "db", "update"], check=True)
        print("[+] Grype database updated")
    except subprocess.CalledProcessError as e:
        print(f"[!] Grype DB update failed: {e.stderr}")
    app.run(host="0.0.0.0", port=8080)
