import os
from core.variables import all_repo_scans_folder, local_bin, env, all_resources_folder
from vuln_scan.vuln_check import check_vuln_file
from vuln_scan.trivy_vuln_check import check_vuln_file_trivy
from vuln_scan.get_vulns_count import vuln_count
from file_system.file_save import save_files, attest_sbom, sign_attest, key_generating
from utils.folder_lock import repo_lock
from utils.helpers import load_json
from utils.cleanup import cleanup_scan_data
from validation.secrets_manager import read_secret
from file_system.summary_generator import generate_summary
from file_system.repo_history_tracking import track_repo_history
from logs.audit_trail import save_audit_trail
from external_storage.external_storage_send import send_files_to_external_storage

def save_scan_files(audit_trail, current_repo, syft_sbom_file, semgrep_sast_report, trivy_report, grype_vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author, tool_versions, scan_root, timestamp, exclusions_file, semgrep_sast_ruleset):
    secret_type = "cosign_key"
    cosign_key = read_secret(secret_type)

    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")
    # The COSIGN_PASSWORD used to encrypt the priv key
    env["COSIGN_PASSWORD"] = cosign_key

    repo_name = current_repo.replace("/", "_")

    scan_dir = os.path.join(all_resources_folder, all_repo_scans_folder, organization, repo_name, timestamp)
    repo_dir = os.path.join(all_resources_folder, all_repo_scans_folder, organization, repo_name)

    syft_sbom_path = os.path.join(scan_dir, f"{repo_name}_syft_sbom_cyclonedx.json")
    semgrep_sast_report_path = os.path.join(scan_dir, f"{repo_name}_semgrep_sast_report.json")
    trivy_report_path = os.path.join(scan_dir, f"{repo_name}_trivy_report.json")
    grype_path = os.path.join(scan_dir, f"{repo_name}_grype_vulns_cyclonedx.json")
    prio_path = os.path.join(scan_dir, f"{repo_name}_prio_vuln_data.json")
    summary_report_path = os.path.join(scan_dir, f"{repo_name}_summary_report.json")
    audit_trail_path = os.path.join(scan_dir, f"{repo_name}_audit_trail.json")

    exclusions_file_path = os.path.join(repo_dir, f"{repo_name}_exclusions_file.json")
    repo_history_path = os.path.join(repo_dir, f"{repo_name}_repo_history.json")

    syft_att_sig_path = f"{syft_sbom_path}_att.sig"
    syft_sbom_attestation_path = f"{syft_sbom_path}.att"

    trivy_att_sig_path = f"{trivy_report_path}_att.sig"
    trivy_sbom_attestation_path = f"{trivy_report_path}.att"

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
    
    syft_sbom_json = load_json(syft_sbom_file)
    semgrep_sast_report_json = load_json(semgrep_sast_report)
    trivy_report_json = load_json(trivy_report)
    exclusions_file_json = load_json(exclusions_file)

    def repo_files():
        if not os.path.exists(cosign_key_path) or not os.path.exists(cosign_pub_path):
            key_generating(audit_trail, alerts_list, repo_name, scan_dir, cosign_key_path, cosign_pub_path, alert_path)
        
        summary_report = generate_summary(audit_trail, syft_sbom_json, grype_vulns_cyclonedx_json_data, prio_vuln_data, semgrep_sast_report_json, trivy_report_json, exclusions_file_json, tool_versions, scan_root, semgrep_sast_ruleset)
        save_files(audit_trail, grype_path, grype_vulns_cyclonedx_json_data, prio_path, prio_vuln_data, alert_path, alert_system_json, syft_sbom_path, syft_sbom_json, semgrep_sast_report_path, semgrep_sast_report_json, trivy_report_path, trivy_report_json, summary_report_path, summary_report, exclusions_file_path, exclusions_file_json)
        
        # Handles attestation of syft and trivy SBOMs
        syft_attestation_verified = handle_ingested_data(audit_trail, alerts_list, cosign_key_path, cosign_pub_path, syft_sbom_path, syft_sbom_attestation_path, syft_att_sig_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)
        trivy_attestation_verified = handle_ingested_data(audit_trail, alerts_list, cosign_key_path, cosign_pub_path, trivy_report_path, trivy_sbom_attestation_path, trivy_att_sig_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)

        # Handles counting vulnerabilities and exclusions
        trivy_crit_count, trivy_high_count, trivy_medium_count, trivy_low_count, trivy_unknown_count, trivy_misconf_count, trivy_secret_count = check_vuln_file_trivy(trivy_report_path, exclusions_file_path)
        grype_critical_count, grype_high_count, grype_medium_count, grype_low_count, grype_unknown_count = check_vuln_file(audit_trail, alerts_list, grype_path, alert_path, repo_name, trivy_crit_count, trivy_high_count, trivy_medium_count, trivy_low_count, trivy_unknown_count, trivy_misconf_count, trivy_secret_count, exclusions_file_path)
        vulns_found = vuln_count(audit_trail, semgrep_sast_report_json, trivy_report_json, exclusions_file_json, grype_critical_count, grype_high_count, grype_medium_count, grype_low_count, grype_unknown_count, trivy_crit_count, trivy_high_count, trivy_medium_count, trivy_low_count, trivy_unknown_count, trivy_misconf_count, trivy_secret_count)
        
        audit_trail_hash = save_audit_trail(audit_trail_path, audit_trail)
        track_repo_history(audit_trail_hash, repo_history_path, timestamp, commit_sha, vulns_found, syft_sbom_attestation_path, syft_sbom_path, syft_attestation_verified, trivy_sbom_attestation_path, trivy_report_path, trivy_attestation_verified, alerts_list)

    repo_lock(repo_dir, repo_files)
    
    if os.environ.get("external_storage_enabled", "False").lower() == "true":
        send_files_to_external_storage(scan_dir, scan_dir)
        send_files_to_external_storage(exclusions_file_path, repo_dir)
        send_files_to_external_storage(alert_path, repo_dir)

    cleanup_scan_data()

def handle_ingested_data(audit_trail, alerts_list, cosign_key_path, cosign_pub_path, sbom_path, sbom_attestation_path, att_sig_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author):
    attest_sbom(audit_trail, alerts_list, cosign_key_path, sbom_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)
    attestation_verified = sign_attest(audit_trail, alerts_list, cosign_key_path, cosign_pub_path, att_sig_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)
    return attestation_verified