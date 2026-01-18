import os
from core.variables import *
from vuln_scan.get_vulns_count import check_vuln_files
from file_system.file_save import save_files, attest_sbom, sign_attest, key_generating
from utils.folder_lock import repo_lock
from utils.helpers import load_json
from utils.cleanup import cleanup_scan_data
from validation.secrets_manager import read_secret
from file_system.summary_generator import generate_summary
from file_system.repo_history_tracking import track_repo_history
from logs.audit_trail import save_audit_trail
from logs.export_logs import log_exporter
from external_storage.external_storage_send import send_files_to_external_storage
from alerts.alert_on_severity import check_alert_on_severity

def save_scan_files(audit_trail, current_repo, syft_sbom_file, semgrep_sast_report, trivy_report, grype_vulns_cyclonedx_json_data, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author, tool_versions, scan_root, timestamp, semgrep_sast_ruleset, fail_on_severity):
    secret_type = "cosign_key"
    cosign_key = read_secret(secret_type)

    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")
    # The COSIGN_PASSWORD used to encrypt the priv key
    env["COSIGN_PASSWORD"] = cosign_key

    repo_name = current_repo.replace("/", "_")

    scan_dir = os.path.join(all_resources_folder, all_repo_scans_folder, organization, repo_name, timestamp)
    repo_dir = os.path.join(all_resources_folder, all_repo_scans_folder, organization, repo_name)

    syft_sbom_path = os.path.join(scan_dir, f"{repo_name}{syft_sbom_path_ending}")
    semgrep_sast_report_path = os.path.join(scan_dir, f"{repo_name}{semgrep_sast_report_path_ending}")
    trivy_report_path = os.path.join(scan_dir, f"{repo_name}{trivy_report_path_ending}")
    grype_path = os.path.join(scan_dir, f"{repo_name}{grype_path_ending}")
    prio_path = os.path.join(scan_dir, f"{repo_name}{prio_path_ending}")
    summary_report_path = os.path.join(scan_dir, f"{repo_name}{summary_report_path_ending}")
    audit_trail_path = os.path.join(scan_dir, f"{repo_name}{audit_trail_path_ending}")

    exclusions_file_path = os.path.join(repo_dir, f"{repo_name}{exclusions_file_path_ending}")
    repo_history_path = os.path.join(repo_dir, f"{repo_name}{repo_history_path_ending}")

    syft_att_sig_path = f"{syft_sbom_path}{att_sig_path_ending}"
    syft_sbom_attestation_path = f"{syft_sbom_path}{attestation_path_ending}"

    trivy_att_sig_path = f"{trivy_report_path}{att_sig_path_ending}"
    trivy_sbom_attestation_path = f"{trivy_report_path}{attestation_path_ending}"

    cosign_key_path = os.path.join(scan_dir, f"{repo_name}{cosign_key_path_ending}")
    cosign_pub_path = os.path.join(scan_dir, f"{repo_name}{cosign_pub_path_ending}")

    rulesets = {}

    tool_versions["grype_version"] = GRYPE_VERSION
    tool_versions["cosign_version"] = COSIGN_VERSION
    tool_versions["patchhound_version"] = patchhound_version
    
    rulesets["semgrep"] = semgrep_sast_ruleset

    
    os.makedirs(scan_dir, exist_ok=True)

    if alert_system_webhook:
        alert_system_json = {
            "alert_system_webhook": alert_system_webhook
        }
        alert_path = os.path.join(repo_dir, f"{repo_name}{alert_path_ending}")

        print(f"[+] Alert system set for: {repo_name}")

    if fail_on_severity:
        fail_on_severity_json = {
            "fail_on_severity": fail_on_severity
        }
        
        fail_on_severity_path = os.path.join(scan_dir, f"{repo_name}{fail_on_severity_path_ending}")

    alerts_list = []
    
    syft_sbom_json = load_json(syft_sbom_file)
    trivy_report_json = load_json(trivy_report)
    semgrep_sast_report_json = load_json(semgrep_sast_report)

    def repo_files():
        if not os.path.exists(cosign_key_path) or not os.path.exists(cosign_pub_path):
            key_generating(audit_trail, alerts_list, repo_name, scan_dir, cosign_key_path, cosign_pub_path, alert_path)
        
        save_files(audit_trail, grype_path, grype_vulns_cyclonedx_json_data, prio_path, prio_vuln_data, alert_path, alert_system_json, syft_sbom_path, syft_sbom_json, semgrep_sast_report_path, semgrep_sast_report_json, trivy_report_path, trivy_report_json, fail_on_severity_json, fail_on_severity_path)

        excluded_vuln_counter, excluded_misconf_counter, excluded_exposed_secret_counter, vuln_counter, misconf_counter, exposed_secret_counter, excluded_kev_vuln_counter, kev_vuln_counter = generate_summary(audit_trail, repo_name, syft_sbom_path, grype_path, prio_path, semgrep_sast_report_path, trivy_report_path, exclusions_file_path, summary_report_path, tool_versions, rulesets)

        # Handles attestation of syft and trivy SBOMs
        syft_attestation_verified = handle_ingested_data(audit_trail, alerts_list, cosign_key_path, cosign_pub_path, syft_sbom_path, syft_sbom_attestation_path, syft_att_sig_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)
        trivy_attestation_verified = handle_ingested_data(audit_trail, alerts_list, cosign_key_path, cosign_pub_path, trivy_report_path, trivy_sbom_attestation_path, trivy_att_sig_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)

        # Handles counting vulnerabilities and exclusions
        vulns_found = check_vuln_files(audit_trail, grype_path, trivy_report_path, semgrep_sast_report_path, exclusions_file_path, excluded_vuln_counter, excluded_misconf_counter, excluded_exposed_secret_counter, vuln_counter, misconf_counter, exposed_secret_counter, excluded_kev_vuln_counter, kev_vuln_counter)

        check_alert_on_severity(audit_trail, alerts_list, alert_path, fail_on_severity_path, repo_name, grype_path, trivy_report_path, semgrep_sast_report_path, exclusions_file_path)

        audit_trail_hash = save_audit_trail(audit_trail_path, audit_trail)
        track_repo_history(audit_trail_hash, repo_history_path, timestamp, commit_sha, vulns_found, syft_sbom_attestation_path, syft_sbom_path, syft_attestation_verified, trivy_sbom_attestation_path, trivy_report_path, trivy_attestation_verified, summary_report_path, alerts_list)

    repo_lock(repo_dir, repo_files)
    
    if os.environ.get("external_storage_enabled", "False").lower() == "true":
        send_files_to_external_storage(scan_dir, scan_dir)
        send_files_to_external_storage(alert_path, repo_dir)

    #cleanup_scan_data()

    new_entry = {
        "message": "Scan completed",
        "level": "info",
        "module": "save_scan_files",
    }
    log_exporter(new_entry)
    print("[+] Scan completed")

def handle_ingested_data(audit_trail, alerts_list, cosign_key_path, cosign_pub_path, sbom_path, sbom_attestation_path, att_sig_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author):
    attest_sbom(audit_trail, alerts_list, cosign_key_path, sbom_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)
    attestation_verified = sign_attest(audit_trail, alerts_list, cosign_key_path, cosign_pub_path, att_sig_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)
    return attestation_verified