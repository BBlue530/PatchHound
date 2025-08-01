import os
import json
from datetime import datetime
from filelock import FileLock
from core.Variables import all_repo_scans_folder, cosign_password, local_bin, env
from logs.Log import log_event
from vuln_scan.Vuln_Check import check_vuln_file
from utils.File_Save import save_files, attest_sbom, sign_attest, key_generating

def save_scan_files(current_repo, sbom_file, vulns_cyclonedx_json, prio_vuln_data, token_key, alert_system_webhook, commit_sha, commit_author):
    
    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")
    env["COSIGN_PASSWORD"] = cosign_password

    repo_name = current_repo.replace("/", "_")
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    scan_dir = os.path.join(all_repo_scans_folder, token_key, repo_name, timestamp)
    repo_dir = os.path.join(all_repo_scans_folder, token_key, repo_name)

    sbom_path = os.path.join(scan_dir, f"{repo_name}_sbom_cyclonedx.json")
    grype_path = os.path.join(scan_dir, f"{repo_name}_vulns_cyclonedx.json")
    prio_path = os.path.join(scan_dir, f"{repo_name}_prio_vuln_data.json")

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

    cosign_lock = FileLock(os.path.join(repo_dir, "cosign_key.lock"))
    with cosign_lock:
        if not os.path.exists(cosign_key_path) or not os.path.exists(cosign_pub_path):
            key_generating(repo_name, scan_dir, cosign_key_path, cosign_pub_path, alert_path, repo_dir, timestamp, commit_sha, commit_author)

    if hasattr(sbom_file, 'read'):
        sbom_file.seek(0)
        sbom_json = json.load(sbom_file)
    elif isinstance(sbom_file, bytes):
        sbom_json = json.loads(sbom_file.decode('utf-8'))
    elif isinstance(sbom_file, str):
        sbom_json = json.loads(sbom_file)
    else:
        sbom_json = sbom_file

    save_files(grype_path, vulns_cyclonedx_json, prio_path, prio_vuln_data, alert_path, alert_system_json, sbom_path, sbom_json)
    
    attest_sbom(cosign_key_path, sbom_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)

    sign_attest(cosign_key_path, att_sig_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)

    check_vuln_file(grype_path, alert_path, repo_name)
    
    message = f"[+] Scan of '{repo_name}_sbom_cyclonedx.json' Completed"
    log_event(repo_dir, repo_name, timestamp, message, commit_sha, commit_author)