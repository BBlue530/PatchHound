from flask import jsonify
import json
import os
import subprocess
import json
from core.Variables import env
from logs.Alerts import alert_event_system
from logs.Log import log_event
from utils.Helpers import file_stable_check

def save_files(grype_path, vulns_cyclonedx_json, prio_path, prio_vuln_data, alert_path, alert_system_json, sbom_path, sbom_json, sast_report_path, sast_report_json, trivy_report_path, trivy_report_json, summary_report_path, summary_report, exclusions_file_path, exclusions_file_json):
    with open(alert_path, "w") as f:
        json.dump(alert_system_json, f, indent=4)
    file_stable_check(alert_path)

    with open(sbom_path, "w") as f:
        json.dump(sbom_json, f, indent=4)
    file_stable_check(sbom_path)

    with open(sast_report_path, "w") as f:
        json.dump(sast_report_json, f, indent=4)
    file_stable_check(sast_report_path)

    with open(trivy_report_path, "w") as f:
        json.dump(trivy_report_json, f, indent=4)
    file_stable_check(trivy_report_path)

    with open(grype_path, "w") as f:
        json.dump(vulns_cyclonedx_json, f, indent=4)
    file_stable_check(grype_path)

    with open(prio_path, "w") as f:
        json.dump(prio_vuln_data, f, indent=4)
    file_stable_check(prio_path)

    with open(summary_report_path, "w") as f:
        json.dump(summary_report, f, indent=4)
    file_stable_check(summary_report_path)

    with open(exclusions_file_path, "w") as f:
        json.dump(exclusions_file_json, f, indent=4)
    file_stable_check(exclusions_file_path)

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

def sign_image(cosign_key_path, image_sig_path, image_digest_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author):
    try:
        subprocess.run(
            [
                "cosign", "sign-blob",
                "-y",
                "--key", cosign_key_path,
                "--output-signature", image_sig_path,
                image_digest_path
            ],
            check=True,
            env=env
        )
        print(f"[+] Image signed: {image_sig_path}")
    except subprocess.CalledProcessError as e:
        message = f"[!] Failed to sign image for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Signature Fail"
        print(message)
        alert_event_system(message, alert, alert_path)
        log_event(repo_dir, repo_name, timestamp, message, commit_sha, commit_author)

def verify_image(cosign_pub_path, image_sig_path, image_digest_path_verify, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author):
    try:
        subprocess.run(
            [
                "cosign", "verify-blob",
                "--key", cosign_pub_path,
                "--signature", image_sig_path,
                image_digest_path_verify
            ],
            check=True,
            env=env
        )
        print(f"[+] Image verified: {image_sig_path}")
        verify_image_status = jsonify({"verify_image_status": "image verified and is trusted"}), 200
        return verify_image_status
    except subprocess.CalledProcessError as e:
        message = f"[!] Failed to verify image for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Verification Fail"
        print(message)
        alert_event_system(message, alert, alert_path)
        log_event(repo_dir, repo_name, timestamp, message, commit_sha, commit_author)
        verify_image_status = jsonify({"verify_image_status": "image verification mismatch and is not trusted"}), 422
        return verify_image_status