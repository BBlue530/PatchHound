import json
import os
import subprocess
from filelock import FileLock
from core.Variables import env
from logs.Alerts import alert_event_system
from logs.Log import log_event

def save_files(grype_path, vulns_cyclonedx_json, prio_path, prio_vuln_data, alert_path, alert_system_json, sbom_path, sbom_json):

    alert_lock = FileLock(alert_path + ".lock")
    with alert_lock:
        with open(alert_path, "w") as f:
            json.dump(alert_system_json, f, indent=4)

    with open(sbom_path, "w") as f:
        json.dump(sbom_json, f, indent=4)
    
    with open(grype_path, "w") as f:
        json.dump(vulns_cyclonedx_json, f, indent=4)

    with open(prio_path, "w") as f:
        json.dump(prio_vuln_data, f, indent=4)

def attest_sbom(cosign_key_path, sbom_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author):
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

def sign_attest(cosign_key_path, att_sig_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author):
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

def key_generating(repo_name, scan_dir, cosign_key_path, cosign_pub_path, alert_path, repo_dir, timestamp, commit_sha, commit_author):
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