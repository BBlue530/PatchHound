import os
import json
from datetime import datetime
import subprocess
from Variables import all_repo_scans_folder, cosign_password, local_bin, env
from Alerts import alert_event_system
from Log import log_event
from Vuln_Check import check_vuln_file

def save_scan_files(current_repo, sbom_file, vulns_cyclonedx_json, prio_vuln_data, license_key, alert_system_webhook, commit_sha, commit_author):
    
    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")
    env["COSIGN_PASSWORD"] = cosign_password

    repo_name = current_repo.replace("/", "_")
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    scan_dir = os.path.join(all_repo_scans_folder, license_key, repo_name, timestamp)
    repo_dir = os.path.join(all_repo_scans_folder, license_key, repo_name)

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
        with open(alert_path, "w") as f:
            json.dump(alert_system_json, f, indent=4)
        print(f"[+] Alert system set for: {repo_name}")

    if not os.path.exists(cosign_key_path) or not os.path.exists(cosign_pub_path):
        print(f"[~] Generating Cosign key for repo: {repo_name}")
        try:
            subprocess.run(
                ["cosign", "generate-key-pair"],
                cwd=scan_dir,
                check=True,
                env=env
            )
            os.rename(os.path.join(scan_dir, "cosign.key"), cosign_key_path)
            os.rename(os.path.join(scan_dir, "cosign.pub"), cosign_pub_path)
            print(f"[+] Cosign key generated for repo: {repo_name}")

        except subprocess.CalledProcessError as e:
            message = f"[!] Failed to generate Cosign key for repo: {repo_name} {e.stderr}!"
            alert = "Workflow : Signature Fail"
            print(message)
            alert_event_system(message, alert, alert_path)
            log_event(repo_dir, repo_name, timestamp, message, commit_sha, commit_author)
            return

    if hasattr(sbom_file, 'read'):
        sbom_file.seek(0)
        sbom_json = json.load(sbom_file)
    elif isinstance(sbom_file, bytes):
        sbom_json = json.loads(sbom_file.decode('utf-8'))
    elif isinstance(sbom_file, str):
        sbom_json = json.loads(sbom_file)
    else:
        sbom_json = sbom_file

    with open(sbom_path, "w") as f:
        json.dump(sbom_json, f, indent=4)

    try:
        subprocess.run(
            [
                "cosign", "attest-blob",
                "-y",
                "--key", cosign_key_path,
                "--predicate", sbom_path,
                "--type", "cyclonedx",
                "--output-signature", sbom_attestation_path,
                sbom_path
            ],
            check=True,
            env=env
        )
        print(f"[+] SBOM attested: {sbom_attestation_path}")
    except subprocess.CalledProcessError as e:
        message = f"[!] Failed to attest SBOM for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Signature Fail"
        print(message)
        alert_event_system(message, alert, alert_path)
        log_event(repo_dir, repo_name, timestamp, message, commit_sha, commit_author)

    try:
        subprocess.run(
            [
                "cosign", "sign-blob",
                "-y",
                "--key", cosign_key_path,
                "--output-signature", att_sig_path,
                sbom_attestation_path
            ],
            check=True,
            env=env
        )
        print(f"[+] Attestation signed: {att_sig_path}")
    except subprocess.CalledProcessError as e:
        message = f"[!] Failed to sign Attestation for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Signature Fail"
        print(message)
        alert_event_system(message, alert, alert_path)
        log_event(repo_dir, repo_name, timestamp, message, commit_sha, commit_author)

    with open(grype_path, "w") as f:
        json.dump(vulns_cyclonedx_json, f, indent=4)

    with open(prio_path, "w") as f:
        json.dump(prio_vuln_data, f, indent=4)

    check_vuln_file(grype_path, alert_path, repo_name)
    
    message = f"[+] Scan of '{repo_name}_sbom_cyclonedx.json' Completed"
    log_event(repo_dir, repo_name, timestamp, message, commit_sha, commit_author)