import os
from core.variables import all_repo_scans_folder, local_bin, env
from logs.log import log_event
from vuln_scan.vuln_check import check_vuln_file
from vuln_scan.trivy_vuln_check import check_vuln_file_trivy
from vuln_scan.get_vulns_count import vuln_count
from file_system.file_save import save_files, attest_sbom, sign_attest, key_generating
from utils.folder_lock import repo_lock
from utils.helpers import load_json
from validation.secrets_manager import read_secret
from file_system.summary_generator import generate_summary
from file_system.repo_history_tracking import track_repo_history

def save_scan_files(current_repo, sbom_file, sast_report, trivy_report, vulns_cyclonedx_json, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author, timestamp, exclusions_file):
    secret_type = "cosign_key"
    cosign_key = read_secret(secret_type)

    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")
    env["COSIGN_PASSWORD"] = cosign_key

    repo_name = current_repo.replace("/", "_")

    scan_dir = os.path.join(all_repo_scans_folder, organization, repo_name, timestamp)
    repo_dir = os.path.join(all_repo_scans_folder, organization, repo_name)

    sbom_path = os.path.join(scan_dir, f"{repo_name}_sbom_cyclonedx.json")
    sast_report_path = os.path.join(scan_dir, f"{repo_name}_sast_report.json")
    trivy_report_path = os.path.join(scan_dir, f"{repo_name}_trivy_report.json")
    grype_path = os.path.join(scan_dir, f"{repo_name}_vulns_cyclonedx.json")
    prio_path = os.path.join(scan_dir, f"{repo_name}_prio_vuln_data.json")
    summary_report_path = os.path.join(scan_dir, f"{repo_name}_summary_report.json")
    exclusions_file_path = os.path.join(repo_dir, f"{repo_name}_exclusions_file.json")
    repo_history_path = os.path.join(repo_dir, f"{repo_name}_repo_history.json")

    att_sig_path = f"{sbom_path}_att.sig"
    sbom_attestation_path = f"{sbom_path}.att"

    cosign_key_path = os.path.join(scan_dir, f"{repo_name}.key")
    cosign_pub_path = os.path.join(scan_dir, f"{repo_name}.pub")
    
    os.makedirs(scan_dir, exist_ok=True)

    if alert_system_webhook:
        alert_system_json = {
            "alert_system_webhook": alert_system_webhook
        }
        alert_path = os.path.join(repo_dir, f"{repo_name}_alert.json")

        print(f"[+] Alert system set for: {repo_name}")

    alerts_list = []
    
    sbom_json = load_json(sbom_file)
    sast_report_json = load_json(sast_report)
    trivy_report_json = load_json(trivy_report)
    exclusions_file_json = load_json(exclusions_file)

    def repo_files():
        if not os.path.exists(cosign_key_path) or not os.path.exists(cosign_pub_path):
            key_generating(alerts_list, repo_name, scan_dir, cosign_key_path, cosign_pub_path, alert_path, repo_dir, timestamp, commit_sha, commit_author)
        summary_report = generate_summary(vulns_cyclonedx_json, prio_vuln_data, sast_report_json, trivy_report_json, exclusions_file_json)
        save_files(grype_path, vulns_cyclonedx_json, prio_path, prio_vuln_data, alert_path, alert_system_json, sbom_path, sbom_json, sast_report_path, sast_report_json, trivy_report_path, trivy_report_json, summary_report_path, summary_report, exclusions_file_path, exclusions_file_json)
        attest_sbom(alerts_list, cosign_key_path, sbom_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)
        attestation_verified = sign_attest(alerts_list, cosign_key_path, cosign_pub_path, att_sig_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)
        trivy_crit_count, trivy_high_count, trivy_medium_count, trivy_low_count, trivy_unknown_count, trivy_misconf_count, trivy_secret_count = check_vuln_file_trivy(trivy_report_path, exclusions_file_path)
        grype_critical_count, grype_high_count, grype_medium_count, grype_low_count, grype_unknown_count = check_vuln_file(alerts_list, grype_path, alert_path, repo_name, trivy_crit_count, trivy_high_count, trivy_medium_count, trivy_low_count, trivy_unknown_count, trivy_misconf_count, trivy_secret_count, exclusions_file_path)
        vulns_found = vuln_count(sast_report_json, trivy_report_json, exclusions_file_json, grype_critical_count, grype_high_count, grype_medium_count, grype_low_count, grype_unknown_count, trivy_crit_count, trivy_high_count, trivy_medium_count, trivy_low_count, trivy_unknown_count, trivy_misconf_count, trivy_secret_count)
        track_repo_history(repo_history_path, timestamp, commit_sha, vulns_found, sbom_attestation_path, sbom_path, attestation_verified, alerts_list)

    repo_lock(repo_dir, repo_files)
    
    message = f"[+] Scan of '{repo_name}_sbom_cyclonedx.json' Completed"
    log_event(repo_dir, repo_name, timestamp, message, commit_sha, commit_author)