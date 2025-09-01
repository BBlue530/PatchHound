import os
import json
from datetime import datetime
import subprocess
from core.variables import all_resources_folder, all_repo_scans_folder, all_image_signature_folder, scheduled_event_commit_sha, scheduled_event_commit_author, local_bin, env
from vuln_scan.kev_catalog import compare_kev_catalog
from logs.alerts import alert_event_system
from utils.helpers import extract_cve_ids
from logs.audit_trail import save_audit_trail, audit_trail_event
from validation.hash_verify import verify_sha

def sbom_validation():
    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")

    audit_trail = []

    repo_scans_dir = os.path.join(all_resources_folder, all_repo_scans_folder)
    image_sign_dir = os.path.join(all_resources_folder, all_image_signature_folder)

    if not os.path.isdir(repo_scans_dir):
        print(f"[~] Creating missing scans folder: {repo_scans_dir}")
        os.makedirs(repo_scans_dir, exist_ok=True)

    if not os.path.isdir(image_sign_dir):
        print(f"[~] Creating missing scans folder: {image_sign_dir}")
        os.makedirs(image_sign_dir, exist_ok=True)
    
    # List all directories inside repo_scans_dir aka the token keys
    for organization in os.listdir(repo_scans_dir):
        token_path = os.path.join(repo_scans_dir, organization)
        if not os.path.isdir(token_path):
            continue
        print(f"[~] Scanning for token key: {organization}")

        # List all directories inside the token key dir which will be the repo_name
        daily_scan = True
        for repo_name in os.listdir(token_path):
            repo_path = os.path.join(token_path, repo_name)
            if not os.path.isdir(repo_path):
                continue

            # List all directories inside the repo_name dir and sort them.
            # Latest is the first since timestamp sort themself
            timestamp_folders = sorted([f for f in os.listdir(repo_path) if os.path.isdir(os.path.join(repo_path, f))],reverse=True)

            if not timestamp_folders:
                print(f"[!] No scans found for repo: {repo_name}")
                continue
            
            timestamp_folder = timestamp_folders[0]
            
            # Create the full path for the latest scan inside the repo
            # repo_scans_dir, organization, repo_name, timestamp_folders, {repo_name}_sbom_cyclonedx.json
            latest_scan_dir = os.path.join(repo_path, timestamp_folder)

            sbom_path = os.path.join(latest_scan_dir, f"{repo_name}_sbom_cyclonedx.json")
            alert_path = os.path.join(repo_path, f"{repo_name}_alert.json")
            exclusions_file_path = os.path.join(repo_path, f"{repo_name}_exclusions_file.json")
            att_sig_path = f"{sbom_path}_att.sig"
            sbom_att_path = f"{sbom_path}.att"
            cosign_pub_path = os.path.join(latest_scan_dir, f"{repo_name}.pub")

            vulns_output_path = os.path.join(latest_scan_dir, f"{repo_name}_vulns_cyclonedx.json")
            prio_output_path = os.path.join(latest_scan_dir, f"{repo_name}_prio_vuln_data.json")

            if not os.path.exists(sbom_path):
                daily_scan = False
                audit_trail_event(audit_trail, "SBOM_EXISTS", {
                "status": "fail",
                })
                message = f"[!] SBOM missing for repo: {repo_name}"
                alert = "Scheduled Event : SBOM Missing"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            if not os.path.exists(sbom_att_path):
                daily_scan = False
                audit_trail_event(audit_trail, "ATTESTATION_EXISTS", {
                "status": "fail",
                })
                message = f"[!] Attestation missing for SBOM in repo: {repo_name}"
                alert = "Scheduled Event : Attestation Missing"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            if not os.path.exists(att_sig_path):
                daily_scan = False
                audit_trail_event(audit_trail, "SIGNATURE_EXISTS", {
                "status": "fail",
                })
                message = f"[!] Signature missing for Attestation in repo: {repo_name}"
                alert = "Scheduled Event : Signature Missing"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            try:
                subprocess.run(
                    [
                        "cosign", "verify-blob-attestation",
                        "--key", cosign_pub_path,
                        "--signature", sbom_att_path,
                        "--type", "cyclonedx",
                        sbom_path
                    ],
                    check=True,
                    env=env
                )
                print(f"[+] Verified SBOM attestation for repo: {repo_name}")
            except subprocess.CalledProcessError:
                daily_scan = False
                audit_trail_event(audit_trail, "VERIFY_ATTESTATION", {
                "status": "fail",
                })
                message = f"[!] Attestation verification failed for repo: {repo_name}!"
                alert = "Scheduled Event : Attestation Fail"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            try:
                subprocess.run(
                    [
                        "cosign", "verify-blob",
                        "--key", cosign_pub_path,
                        "--signature", att_sig_path,
                        sbom_att_path
                    ],
                    check=True,
                    env=env
                )
                print(f"[+] Verified Attestation signature for repo: {repo_name}")
            except subprocess.CalledProcessError:
                daily_scan = False
                audit_trail_event(audit_trail, "VERIFY_ATTESTATION_SIGNATURE", {
                "status": "fail",
                })
                message = f"[!] Signature for Attestation failed for repo: {repo_name}!"
                alert = "Scheduled Event : Signature Fail"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            print(f"[~] Verifying file hash for repo: {repo_name}")
            verify_sha(audit_trail, repo_path, timestamp_folder, repo_name, alert_path)

            print(f"[~] Scanning latest SBOM for repo: {repo_name}")
            try:
                vulns_cyclonedx_json = subprocess.run(
                    ["grype", sbom_path, "-o", "cyclonedx-json"],
                    capture_output=True,
                    text=True,
                    check=True
                )

                vulns_cyclonedx_json_data = json.loads(vulns_cyclonedx_json.stdout)

                previous_vulns_data = None
                
                if os.path.exists(vulns_output_path):
                    with open(vulns_output_path, "r") as f:
                        try:
                            previous_vulns_data = json.load(f)
                        except json.JSONDecodeError:
                            previous_vulns_data = None

                with open(exclusions_file_path, "r") as f:
                    exclusions_data = json.load(f)
                excluded_ids = {item["vulnerability"] for item in exclusions_data.get("exclusions", [])}

                current_cve_ids = extract_cve_ids(vulns_cyclonedx_json_data)
                previous_cve_ids = extract_cve_ids(previous_vulns_data) if previous_vulns_data else set()

                new_cves = current_cve_ids - previous_cve_ids

                new_cves_to_alert = new_cves - excluded_ids

                if new_cves_to_alert:
                    daily_scan = False
                    audit_trail_event(audit_trail, "NEW_VULNERABILITIES_FOUND", {
                    "repo": repo_name,
                    "timestamp": timestamp,
                    "vulnerabilities": sorted(list(new_cves_to_alert)),
                    "commit_sha": scheduled_event_commit_sha
                    })
                    audit_trail_event(audit_trail, "EXCLUDED_VULNERABILITIES", {
                    "repo": repo_name,
                    "timestamp": timestamp,
                    "vulnerabilities": sorted(list(excluded_ids))
                    })
                    message = f"[!] New vulnerabilities detected in repo {repo_name}: {', '.join(sorted(new_cves_to_alert))}"
                    alert = "Scheduled Event : New Vulnerabilities Detected"
                    print(message)
                    alert_event_system(audit_trail, message, alert, alert_path)

                with open(vulns_output_path, "w") as f:
                    f.write(vulns_cyclonedx_json.stdout)

                prio_vuln_data = compare_kev_catalog(audit_trail, vulns_cyclonedx_json_data)
                with open(prio_output_path, "w") as f:
                    json.dump(prio_vuln_data, f, indent=4)

                if daily_scan is False:
                    audit_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                    audit_trail_path = os.path.join(latest_scan_dir, f"{repo_name}_audit_trail_{audit_timestamp}.json")
                    save_audit_trail(audit_trail_path, audit_trail)
                print(f"[+] Scan finished for repo: {repo_name}")

            except subprocess.CalledProcessError as e:
                message = f"[!] Scan failed for {repo_name}: {e.stderr}"
                alert = "Scheduled Event : Scan Fail"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)