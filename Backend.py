from flask import Flask, request, jsonify
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
        "vulnerabilities": vulns_json,
        "simplified": simplify_cves(vulns_json)
    })

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

def simplify_cves(vulns_json):
    simplified = {}
    for match in vulns_json.get("matches", []):
        vuln = match.get("vulnerability", {})
        cve = vuln.get("id", "Unknown CVE")
        if cve in simplified:
            continue

        full_cause = vuln.get("description", "No description available").strip().replace('\n', ' ')
        cause = (full_cause[:197] + '...') if len(full_cause) > 200 else full_cause
        
        fix_versions = vuln.get("fix", {}).get("versions", [])
        solution = f"Upgrade to >= {fix_versions[0]}" if fix_versions else "No fix available"
        
        cve_link = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"

        simplified[cve] = {
            "cause": cause,
            "solution": solution,
            "link": cve_link
        }
    return simplified

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
