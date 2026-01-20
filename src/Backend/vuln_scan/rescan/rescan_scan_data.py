import os
import json
from datetime import datetime
import subprocess
from core.variables import *
from vuln_scan.kev_catalog import compare_kev_catalog
from logs.alerts import alert_event_system
from utils.helpers import extract_cve_ids, load_file_data
from logs.audit_trail import save_audit_trail, audit_trail_event
from logs.export_logs import log_exporter
from validation.hash_verify import verify_sha
from validation.file_exist import verify_file_exists
from external_storage.external_storage_send import send_files_to_external_storage
from file_system.summary_generator import add_new_vulns_to_summary
from file_system.repo_history_tracking import update_repo_history
from alerts.alert_on_severity import check_alert_on_severity
from file_system.cleanup.cleanup_scan_data import cleanup_scan_data

def rescan_scan_data(audit_trail, repo_path, timestamp_folder, repo_name, organization):
    rescan_success = True

    repo_timestamp_path = os.path.join(repo_path, timestamp_folder)

    alert_path = os.path.join(repo_path, f"{repo_name}{alert_path_ending}")

    fail_on_severity_path = os.path.join(repo_timestamp_path, f"{repo_name}{fail_on_severity_path_ending}")
    
    syft_sbom_path = os.path.join(repo_timestamp_path, f"{repo_name}{syft_sbom_path_ending}")
    syft_att_sig_path = f"{syft_sbom_path}{att_sig_path_ending}"
    syft_sbom_att_path = f"{syft_sbom_path}{attestation_path_ending}"

    trivy_report_path = os.path.join(repo_timestamp_path, f"{repo_name}{trivy_report_path_ending}")
    trivy_att_sig_path = f"{trivy_report_path}{att_sig_path_ending}"
    trivy_sbom_att_path = f"{trivy_report_path}{attestation_path_ending}"

    exclusions_file_path = os.path.join(repo_path, f"{repo_name}{exclusions_file_path_ending}")

    cosign_pub_path = os.path.join(repo_timestamp_path, f"{repo_name}{cosign_pub_path_ending}")

    grype_vulns_output_path = os.path.join(repo_timestamp_path, f"{repo_name}{grype_path_ending}")
    prio_output_path = os.path.join(repo_timestamp_path, f"{repo_name}{prio_path_ending}")

    summary_report_path = os.path.join(repo_timestamp_path, f"{repo_name}{summary_report_path_ending}")

    repo_history_path = os.path.join(repo_path, f"{repo_name}{repo_history_path_ending}")

    # These are not used anywhere and are just here to make sure they actually exist
    semgrep_sast_report_path = os.path.join(repo_timestamp_path, f"{repo_name}{semgrep_sast_report_path_ending}")
    old_audit_trail_path = os.path.join(repo_timestamp_path, f"{repo_name}{audit_trail_path_ending}")
    cosign_key_path = os.path.join(repo_timestamp_path, f"{repo_name}{cosign_key_path_ending}")

    alerts_list= []

    all_files_exist, files_missing = verify_file_exists([alert_path, syft_sbom_path, syft_att_sig_path, syft_sbom_att_path, trivy_report_path, trivy_att_sig_path, trivy_sbom_att_path, cosign_pub_path, grype_vulns_output_path, prio_output_path, summary_report_path, repo_history_path, semgrep_sast_report_path, old_audit_trail_path, cosign_key_path])

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

        exclusions_data = load_file_data(exclusions_file_path)
        excluded_ids = {item["vulnerability"] for item in exclusions_data.get("exclusions", [])}

        current_cve_ids = extract_cve_ids(grype_vulns_cyclonedx_json_data)
        previous_cve_ids = extract_cve_ids(previous_vulns_data) if previous_vulns_data else set()

        new_cves = current_cve_ids - previous_cve_ids

        new_cves_to_alert = new_cves - excluded_ids

        if new_cves_to_alert:
            new_entry = {
                "message": f"New vulnerabilities detected in repo: {repo_name} Timestamp: {timestamp_folder} [{', '.join(sorted(new_cves_to_alert))}]",
                "level": "error",
                "module": "scheduled_rescan",
            }
            log_exporter(new_entry)
            
            rescan_success = False
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

            check_alert_on_severity(audit_trail, alerts_list, alert_path, fail_on_severity_path, repo_name, grype_vulns_output_path, trivy_report_path, semgrep_sast_report_path, exclusions_file_path)

            add_new_vulns_to_summary(new_cves_to_alert, grype_vulns_cyclonedx_json_data, summary_report_path)
            update_repo_history(audit_trail, repo_name, alert_path, summary_report_path, repo_history_path, timestamp_folder)
            return rescan_success
        else:
            print(f"[+] No new vulnerabilities found in SBOM for repo: {repo_name}")

        prio_vuln_data = compare_kev_catalog(audit_trail, grype_vulns_cyclonedx_json_data, trivy_report_data)

        with open(grype_vulns_output_path, "w") as f:
            json.dump(grype_vulns_cyclonedx_json_data, f, indent=2)

        with open(prio_output_path, "w") as f:
            json.dump(prio_vuln_data, f, indent=4)

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
            send_files_to_external_storage(prio_output_path, s3_bucker_dir_timestamp_folder)
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