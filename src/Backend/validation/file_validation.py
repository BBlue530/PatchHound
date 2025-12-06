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

            alert_path = os.path.join(repo_path, f"{repo_name}_alert.json")

            syft_sbom_path = os.path.join(latest_scan_dir, f"{repo_name}_sbom_cyclonedx.json")
            syft_att_sig_path = f"{syft_sbom_path}_att.sig"
            syft_sbom_att_path = f"{syft_sbom_path}.att"

            trivy_report_path = os.path.join(latest_scan_dir, f"{repo_name}_trivy_report.json")
            trivy_att_sig_path = f"{trivy_report_path}_att.sig"
            trivy_sbom_att_path = f"{trivy_report_path}.att"

            exclusions_file_path = os.path.join(repo_path, f"{repo_name}_exclusions_file.json")

            cosign_pub_path = os.path.join(latest_scan_dir, f"{repo_name}.pub")

            grype_vulns_output_path = os.path.join(latest_scan_dir, f"{repo_name}_vulns_cyclonedx.json")
            prio_output_path = os.path.join(latest_scan_dir, f"{repo_name}_prio_vuln_data.json")

            # Syft checks
            if not os.path.exists(syft_sbom_path):
                daily_scan = False
                audit_trail_event(audit_trail, "SYFT_SBOM_EXISTS", {
                "status": "fail",
                })
                message = f"[!] SYFT_SBOM missing for repo: {repo_name}"
                alert = "Scheduled Event : SYFT_SBOM Missing"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            if not os.path.exists(syft_sbom_att_path):
                daily_scan = False
                audit_trail_event(audit_trail, "SYFT_ATTESTATION_EXISTS", {
                "status": "fail",
                })
                message = f"[!] SYFT_Attestation missing for SBOM in repo: {repo_name}"
                alert = "Scheduled Event : SYFT_Attestation Missing"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            if not os.path.exists(syft_att_sig_path):
                daily_scan = False
                audit_trail_event(audit_trail, "SYFT_SIGNATURE_EXISTS", {
                "status": "fail",
                })
                message = f"[!] SYFT_Signature missing for SYFT_Attestation in repo: {repo_name}"
                alert = "Scheduled Event : SYFT_Signature Missing"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            try:
                subprocess.run(
                    [
                        "cosign", "verify-blob-attestation",
                        "--key", cosign_pub_path,
                        "--signature", syft_sbom_att_path,
                        "--type", "cyclonedx",
                        syft_sbom_path
                    ],
                    check=True,
                    env=env
                )
                print(f"[+] Verified SYFT_SBOM attestation for repo: {repo_name}")
            except subprocess.CalledProcessError:
                daily_scan = False
                audit_trail_event(audit_trail, "SYFT_VERIFY_ATTESTATION", {
                "status": "fail",
                })
                message = f"[!] SYFT_Attestation verification failed for repo: {repo_name}!"
                alert = "Scheduled Event : SYFT_Attestation Fail"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            try:
                subprocess.run(
                    [
                        "cosign", "verify-blob",
                        "--key", cosign_pub_path,
                        "--signature", syft_att_sig_path,
                        syft_sbom_att_path
                    ],
                    check=True,
                    env=env
                )
                print(f"[+] Verified SYFT_Attestation signature for repo: {repo_name}")
            except subprocess.CalledProcessError:
                daily_scan = False
                audit_trail_event(audit_trail, "SYFT_VERIFY_ATTESTATION_SIGNATURE", {
                "status": "fail",
                })
                message = f"[!] SYFT_Signature for SYFT_Attestation failed for repo: {repo_name}!"
                alert = "Scheduled Event : SYFT_Signature Fail"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            # Trivy checks
            if not os.path.exists(trivy_report_path):
                daily_scan = False
                audit_trail_event(audit_trail, "TRVIY_SBOM_EXISTS", {
                "status": "fail",
                })
                message = f"[!] TRVIY_SBOM missing for repo: {repo_name}"
                alert = "Scheduled Event : TRVIY_SBOM Missing"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            if not os.path.exists(trivy_att_sig_path):
                daily_scan = False
                audit_trail_event(audit_trail, "TRVIY_ATTESTATION_EXISTS", {
                "status": "fail",
                })
                message = f"[!] TRVIY_Attestation missing for SBOM in repo: {repo_name}"
                alert = "Scheduled Event : TRVIY_Attestation Missing"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            if not os.path.exists(trivy_sbom_att_path):
                daily_scan = False
                audit_trail_event(audit_trail, "TRVIY_SIGNATURE_EXISTS", {
                "status": "fail",
                })
                message = f"[!] TRVIY_Signature missing for TRVIY_Attestation in repo: {repo_name}"
                alert = "Scheduled Event : TRVIY_Signature Missing"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)
            
            try:
                subprocess.run(
                    [
                        "cosign", "verify-blob-attestation",
                        "--key", cosign_pub_path,
                        "--signature", trivy_sbom_att_path,
                        "--type", "cyclonedx",
                        trivy_report_path
                    ],
                    check=True,
                    env=env
                )
                print(f"[+] Verified TRVIY_SBOM attestation for repo: {repo_name}")
            except subprocess.CalledProcessError:
                daily_scan = False
                audit_trail_event(audit_trail, "TRVIY_VERIFY_ATTESTATION", {
                "status": "fail",
                })
                message = f"[!] TRVIY_Attestation verification failed for repo: {repo_name}!"
                alert = "Scheduled Event : TRVIY_Attestation Fail"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            try:
                subprocess.run(
                    [
                        "cosign", "verify-blob",
                        "--key", cosign_pub_path,
                        "--signature", trivy_att_sig_path,
                        trivy_sbom_att_path
                    ],
                    check=True,
                    env=env
                )
                print(f"[+] Verified TRVIY_Attestation signature for repo: {repo_name}")
            except subprocess.CalledProcessError:
                daily_scan = False
                audit_trail_event(audit_trail, "TRVIY_VERIFY_ATTESTATION_SIGNATURE", {
                "status": "fail",
                })
                message = f"[!] TRVIY_Signature for TRVIY_Attestation failed for repo: {repo_name}!"
                alert = "Scheduled Event : TRVIY_Signature Fail"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(audit_trail, message, alert, alert_path)

            # Verify the hash for the files to prevent tampering
            print(f"[~] Verifying file hash for repo: {repo_name}")
            verify_sha(audit_trail, repo_path, timestamp_folder, repo_name, alert_path)
            
            # Checks for if new vulnerabilities have been found in the packages
            print(f"[~] Scanning latest SYFT_SBOM for repo: {repo_name}")
            try:
                grype_vulns_cyclonedx_json_data = subprocess.run(
                    ["grype", syft_sbom_path, "-o", "cyclonedx-json"],
                    capture_output=True,
                    text=True,
                    check=True
                )

                grype_vulns_cyclonedx_json_data = json.loads(grype_vulns_cyclonedx_json_data.stdout)

                previous_vulns_data = None
                
                if os.path.exists(grype_vulns_output_path):
                    with open(grype_vulns_output_path, "r") as f:
                        try:
                            previous_vulns_data = json.load(f)
                        except json.JSONDecodeError:
                            previous_vulns_data = None

                if os.path.exists(trivy_report_path):
                    with open(trivy_report_path, "r") as f:
                        try:
                            trivy_report_data = json.load(f)
                        except json.JSONDecodeError:
                            trivy_report_data = None

                with open(exclusions_file_path, "r") as f:
                    exclusions_data = json.load(f)
                excluded_ids = {item["vulnerability"] for item in exclusions_data.get("exclusions", [])}

                current_cve_ids = extract_cve_ids(grype_vulns_cyclonedx_json_data)
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

                with open(grype_vulns_output_path, "w") as f:
                    json.dump(grype_vulns_cyclonedx_json_data, f, indent=2)

                prio_vuln_data = compare_kev_catalog(audit_trail, grype_vulns_cyclonedx_json_data, trivy_report_data)
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