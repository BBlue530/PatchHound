import os
import json
from datetime import datetime
import subprocess
from core.variables import *
from vuln_scan.kev_catalog import compare_kev_catalog
from alerts.alerts import alert_event_system
from utils.helpers import extract_cve_ids, extract_kev_cve_ids, load_file_data
from logs.audit_trail import save_audit_trail, audit_trail_event
from logs.export_logs import log_exporter
from validation.hash_verify import verify_sha
from validation.file_exist import verify_file_exists
from external_storage.external_storage_send import send_files_to_external_storage
from file_system.summary_generator import update_summary_rescan
from file_system.repo_history_tracking import update_repo_history_rescan
from alerts.alert_on_severity import check_alert_on_severity
from file_system.cleanup.cleanup_scan_data import cleanup_scan_data

def rescan_scan_data(audit_trail, repo_path, timestamp_folder, repo_name, organization):
    rescan_success = True

    repo_timestamp_path = os.path.join(repo_path, timestamp_folder)

    alert_path = os.path.join(repo_path, f"{repo_name}{alert_path_ending}")
    
    syft_sbom_path = os.path.join(repo_timestamp_path, f"{repo_name}{syft_sbom_path_ending}")
    syft_att_sig_path = f"{syft_sbom_path}{att_sig_path_ending}"
    syft_sbom_att_path = f"{syft_sbom_path}{attestation_path_ending}"

    trivy_report_path = os.path.join(repo_timestamp_path, f"{repo_name}{trivy_report_path_ending}")
    trivy_att_sig_path = f"{trivy_report_path}{att_sig_path_ending}"
    trivy_sbom_att_path = f"{trivy_report_path}{attestation_path_ending}"

    exclusions_file_path = os.path.join(repo_path, f"{repo_name}{exclusions_file_path_ending}")

    cosign_pub_path = os.path.join(repo_timestamp_path, f"{repo_name}{cosign_pub_path_ending}")

    grype_vulns_output_path = os.path.join(repo_timestamp_path, f"{repo_name}{grype_path_ending}")
    prio_vuln_path = os.path.join(repo_timestamp_path, f"{repo_name}{prio_path_ending}")

    summary_report_path = os.path.join(repo_timestamp_path, f"{repo_name}{summary_report_path_ending}")

    repo_history_path = os.path.join(repo_path, f"{repo_name}{repo_history_path_ending}")

    # These are not used anywhere and are just here to make sure they actually exist
    semgrep_sast_report_path = os.path.join(repo_timestamp_path, f"{repo_name}{semgrep_sast_report_path_ending}")
    old_audit_trail_path = os.path.join(repo_timestamp_path, f"{repo_name}{audit_trail_path_ending}")
    cosign_key_path = os.path.join(repo_timestamp_path, f"{repo_name}{cosign_key_path_ending}")

    alerts_list= []

    all_files_exist, files_missing = verify_file_exists([alert_path, syft_sbom_path, syft_att_sig_path, syft_sbom_att_path, trivy_report_path, trivy_att_sig_path, trivy_sbom_att_path, cosign_pub_path, grype_vulns_output_path, prio_vuln_path, summary_report_path, repo_history_path, semgrep_sast_report_path, old_audit_trail_path, cosign_key_path])

    if not all_files_exist:
        new_entry = {
            "message": f"Missing files in repo: {repo_name} timestamp folder: {timestamp_folder}. Files missing: [{files_missing}]",
            "level": "error",
            "module": "scheduled_rescan",
        }
        log_exporter(new_entry)

        audit_trail_event(audit_trail, "MISSING_FILES", {
        "status": "fail",
        "files_missing": files_missing,
        })
        message = f"[!] Missing files in repo: {repo_name} timestamp folder: {timestamp_folder}. Files missing: [{files_missing}]"
        alert = "Scheduled Event : SYFT_Attestation Missing"
        print(f"{message}")
        
        if os.path.exists(alert_path):
            alert_event_system(audit_trail, message, alert, alert_path)

        audit_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        audit_trail_path = os.path.join(repo_timestamp_path, f"{repo_name}_audit_trail_{audit_timestamp}.json")
        save_audit_trail(audit_trail_path, audit_trail)
        return

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
        new_entry = {
            "message": f"SYFT_Attestation verification failed for repo: {repo_name} timestamp_folder: {timestamp_folder}",
            "level": "error",
            "module": "scheduled_rescan",
        }
        log_exporter(new_entry)

        rescan_success = False
        audit_trail_event(audit_trail, "SYFT_VERIFY_ATTESTATION", {
        "status": "fail",
        })
        message = f"[!] SYFT_Attestation verification failed for repo: {repo_name}!"
        alert = "Scheduled Event : SYFT_Attestation Fail"
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
        return rescan_success

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
        new_entry = {
            "message": f"SYFT_Signature for SYFT_Attestation failed for repo: {repo_name} timestamp_folder: {timestamp_folder}",
            "level": "error",
            "module": "scheduled_rescan",
        }
        log_exporter(new_entry)

        rescan_success = False
        audit_trail_event(audit_trail, "SYFT_VERIFY_ATTESTATION_SIGNATURE", {
        "status": "fail",
        })
        message = f"[!] SYFT_Signature for SYFT_Attestation failed for repo: {repo_name}!"
        alert = "Scheduled Event : SYFT_Signature Fail"
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
        return rescan_success
    
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
        new_entry = {
            "message": f"TRVIY_Attestation verification failed for repo: {repo_name} timestamp_folder: {timestamp_folder}",
            "level": "error",
            "module": "scheduled_rescan",
        }
        log_exporter(new_entry)

        rescan_success = False
        audit_trail_event(audit_trail, "TRVIY_VERIFY_ATTESTATION", {
        "status": "fail",
        })
        message = f"[!] TRVIY_Attestation verification failed for repo: {repo_name}!"
        alert = "Scheduled Event : TRVIY_Attestation Fail"
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
        return rescan_success

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
        new_entry = {
            "message": f"TRVIY_Signature for TRVIY_Attestation failed for repo: {repo_name} timestamp_folder: {timestamp_folder}",
            "level": "error",
            "module": "scheduled_rescan",
        }
        log_exporter(new_entry)

        rescan_success = False
        audit_trail_event(audit_trail, "TRVIY_VERIFY_ATTESTATION_SIGNATURE", {
        "status": "fail",
        })
        message = f"[!] TRVIY_Signature for TRVIY_Attestation failed for repo: {repo_name}!"
        alert = "Scheduled Event : TRVIY_Signature Fail"
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
        return rescan_success

    # Verify the hash for the files to prevent tampering
    print(f"[~] Verifying file hash for repo: {repo_name}")
    verify_sha(audit_trail, repo_path, timestamp_folder, repo_name, alert_path)
    print(f"[+] Verified file hash for repo: {repo_name}")
    
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

        if os.path.exists(prio_vuln_path):
            with open(prio_vuln_path, "r") as f:
                try:
                    previous_prio_vuln_data = json.load(f)
                except json.JSONDecodeError:
                    previous_prio_vuln_data = None

        exclusions_data = load_file_data(exclusions_file_path)
        excluded_ids = {item["vulnerability"] for item in exclusions_data.get("exclusions", [])}

        current_cve_ids = extract_cve_ids(grype_vulns_cyclonedx_json_data)
        previous_cve_ids = extract_cve_ids(previous_vulns_data) if previous_vulns_data else set()

        alert_grype_vuln, cves_to_alert, all_new_cves, not_excluded_all_new_cves = alert_rescan(current_cve_ids, previous_cve_ids, excluded_ids, os.environ.get("rescan_alert_vulns"))

        current_prio_vuln_data = compare_kev_catalog(audit_trail, grype_vulns_cyclonedx_json_data, trivy_report_data)

        current_prio_cve_ids = extract_kev_cve_ids(current_prio_vuln_data)
        previous_prio_cve_ids = extract_kev_cve_ids(previous_prio_vuln_data) if previous_prio_vuln_data else set()

        alert_kev_vuln, kev_cves_to_alert, all_new_kev_cves, not_excluded_all_new_kev_cves = alert_rescan(current_prio_cve_ids, previous_prio_cve_ids, excluded_ids, os.environ.get("rescan_alert_kev_vulns"))

        update_summary_rescan(all_new_cves, not_excluded_all_new_cves, all_new_kev_cves, not_excluded_all_new_kev_cves, grype_vulns_cyclonedx_json_data, current_prio_vuln_data, summary_report_path)
        update_repo_history_rescan(audit_trail, repo_name, alert_path, summary_report_path, repo_history_path, timestamp_folder)

        if alert_grype_vuln:
            new_entry = {
                "message": f"Vulnerabilities detected in repo: {repo_name} Timestamp: {timestamp_folder} [{', '.join(sorted(cves_to_alert))}]",
                "level": "error",
                "module": "scheduled_rescan",
            }
            log_exporter(new_entry)
            
            rescan_success = False
            audit_trail_event(audit_trail, "VULNERABILITIES_FOUND", {
            "repo": repo_name,
            "timestamp": timestamp,
            "vulnerabilities": sorted(list(cves_to_alert)),
            "excluded_vulnerabilities": sorted(list(excluded_ids)),
            "commit_sha": scheduled_event_commit_sha
            })

            message = f"[!] Vulnerabilities detected in repo {repo_name}: {', '.join(sorted(cves_to_alert))}"
            alert = "Scheduled Event : Vulnerabilities Detected"
            print(message)
            alert_event_system(audit_trail, message, alert, alert_path)
        else:
            print(f"[+] No vulnerabilities found in SBOM for repo: {repo_name}")

        if alert_kev_vuln:
            new_entry = {
                "message": f"Kev vulnerabilities detected in repo: {repo_name} Timestamp: {timestamp_folder} [{', '.join(sorted(kev_cves_to_alert))}]",
                "level": "error",
                "module": "scheduled_rescan",
            }
            log_exporter(new_entry)
            
            rescan_success = False
            audit_trail_event(audit_trail, "KEV_VULNERABILITIES_FOUND", {
            "repo": repo_name,
            "timestamp": timestamp,
            "vulnerabilities": sorted(list(kev_cves_to_alert)),
            "excluded_vulnerabilities": sorted(list(excluded_ids)),
            "commit_sha": scheduled_event_commit_sha
            })

            message = f"[!] Kev vulnerabilities detected in repo {repo_name}: {', '.join(sorted(kev_cves_to_alert))}"
            alert = "Scheduled Event : Kev Vulnerabilities Detected"
            print(message)
            alert_event_system(audit_trail, message, alert, alert_path)
        else:
            print(f"[+] No kev vulnerabilities found in SBOM for repo: {repo_name}")

        with open(grype_vulns_output_path, "w") as f:
            json.dump(grype_vulns_cyclonedx_json_data, f, indent=2)

        with open(prio_vuln_path, "w") as f:
            json.dump(current_prio_vuln_data, f, indent=4)

        if os.environ.get("external_storage_enabled", "False").lower() == "true":
            # Notes for myself just what is what. Can be ignored and will be removed later.
            # temp_resources_root = "/tmp/s3_resources_xxx"
            # repo_scans_dir = os.path.join(temp_resources_root, all_repo_scans_folder)
            # token_path = os.path.join(repo_scans_dir, organization)
            # repo_path = os.path.join(token_path, repo_name)
            # repo_timestamp_path = os.path.join(repo_path, timestamp_folder)
            s3_bucker_dir_timestamp_folder = os.path.join(all_resources_folder, all_repo_scans_folder, organization, repo_name, timestamp_folder)
            s3_bucker_dir_repo_name = os.path.join(all_resources_folder, all_repo_scans_folder, organization, repo_name)

            send_files_to_external_storage(grype_vulns_output_path, s3_bucker_dir_timestamp_folder)
            send_files_to_external_storage(prio_vuln_path, s3_bucker_dir_timestamp_folder)
            send_files_to_external_storage(summary_report_path, s3_bucker_dir_timestamp_folder)
            send_files_to_external_storage(repo_history_path, s3_bucker_dir_repo_name)

            cleanup_scan_data(audit_trail, s3_bucker_dir_repo_name)
        else:
            cleanup_scan_data(audit_trail, repo_path)
        return rescan_success

    except subprocess.CalledProcessError as e:
        rescan_success = False
        new_entry = {
            "message": f"Scan failed for {repo_name}: {e.stderr}",
            "level": "error",
            "module": "scheduled_rescan",
        }
        log_exporter(new_entry)

        message = f"[!] Scan failed for {repo_name}: {e.stderr}"
        alert = "Scheduled Event : Scan Fail"
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
        return rescan_success
    
def alert_rescan(current_vuln_data, previous_vuln_data, excluded_ids, alert_threshold):

    all_new_vuln_data = current_vuln_data - previous_vuln_data

    not_excluded_all_new_vuln_data = all_new_vuln_data - excluded_ids

    if alert_threshold == all_not_excluded_vulnerabilities:
        if not_excluded_all_new_vuln_data:
            return True, not_excluded_all_new_vuln_data, all_new_vuln_data, not_excluded_all_new_vuln_data

    elif alert_threshold == all_new_vulnerabilities:
        if all_new_vuln_data:
            return True, all_new_vuln_data, all_new_vuln_data, not_excluded_all_new_vuln_data

    elif alert_threshold == all_vulnerabilities:
        if current_vuln_data:
            return True, current_vuln_data, all_new_vuln_data, not_excluded_all_new_vuln_data

    return False, None, all_new_vuln_data, not_excluded_all_new_vuln_data