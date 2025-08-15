import os
from core.Variables import all_repo_scans_folder, cosign_password, local_bin, env
from logs.Log import log_event
from vuln_scan.Vuln_Check import check_vuln_file
from vuln_scan.Trivy_Vuln_Check import check_vuln_file_trivy
from file_system.File_Save import save_files, attest_sbom, sign_attest, key_generating
from utils.Folder_Lock import repo_lock
from utils.Helpers import load_json
from Backend.file_system.Summary_Generator import generate_summary

def save_scan_files(current_repo, sbom_file, sast_report, trivy_report, vulns_cyclonedx_json, prio_vuln_data, organization, alert_system_webhook, commit_sha, commit_author, timestamp, exclusions_file):
    
    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")
    env["COSIGN_PASSWORD"] = cosign_password

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

    sbom_json = load_json(sbom_file)
    sast_report_json = load_json(sast_report)
    trivy_report_json = load_json(trivy_report)
    exclusions_file_json = load_json(exclusions_file)

    def repo_files():
        if not os.path.exists(cosign_key_path) or not os.path.exists(cosign_pub_path):
            key_generating(repo_name, scan_dir, cosign_key_path, cosign_pub_path, alert_path, repo_dir, timestamp, commit_sha, commit_author)
        summary_report = generate_summary(vulns_cyclonedx_json, prio_vuln_data, sast_report_json, trivy_report_json, exclusions_file_json)
        save_files(grype_path, vulns_cyclonedx_json, prio_path, prio_vuln_data, alert_path, alert_system_json, sbom_path, sbom_json, sast_report_path, sast_report_json, trivy_report_path, trivy_report_json, summary_report_path, summary_report, exclusions_file_path, exclusions_file_json)
        attest_sbom(cosign_key_path, sbom_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)
        sign_attest(cosign_key_path, att_sig_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)
        trivy_crit_count, trivy_misconf_count, trivy_secret_count = check_vuln_file_trivy(trivy_report_path, exclusions_file_path)
        check_vuln_file(grype_path, alert_path, repo_name, trivy_crit_count, trivy_misconf_count, trivy_secret_count, exclusions_file_path)

    repo_lock(repo_dir, repo_files)
    
    message = f"[+] Scan of '{repo_name}_sbom_cyclonedx.json' Completed"
    log_event(repo_dir, repo_name, timestamp, message, commit_sha, commit_author)