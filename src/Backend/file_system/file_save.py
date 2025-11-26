from flask import jsonify
import json
import os
import subprocess
import json
from core.variables import env
from logs.alerts import alert_event_system
from utils.helpers import file_stable_check
from logs.audit_trail import audit_trail_event

def save_files(audit_trail, grype_path, grype_vulns_cyclonedx_json_data, prio_path, prio_vuln_data, alert_path, alert_system_json, syft_sbom_path, syft_sbom_json, sast_report_path, sast_report_json, trivy_report_path, trivy_report_json, summary_report_path, summary_report, exclusions_file_path, exclusions_file_json):
    with open(alert_path, "w") as f:
        json.dump(alert_system_json, f, indent=4)
    file_stable_check(alert_path)

    with open(syft_sbom_path, "w") as f:
        json.dump(syft_sbom_json, f, indent=4)
    file_stable_check(syft_sbom_path)

    with open(sast_report_path, "w") as f:
        json.dump(sast_report_json, f, indent=4)
    file_stable_check(sast_report_path)

    with open(trivy_report_path, "w") as f:
        json.dump(trivy_report_json, f, indent=4)
    file_stable_check(trivy_report_path)

    with open(grype_path, "w") as f:
        json.dump(grype_vulns_cyclonedx_json_data, f, indent=4)
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

    audit_trail_event(audit_trail, "FILE_SAVE", {
            "status": "success"
        })

def attest_sbom(audit_trail, alerts_list, cosign_key_path, sbom_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author):
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
        audit_trail_event(audit_trail, "SBOM_ATTESTATION", {
            "status": "success"
        })
        print(f"[+] SBOM attested: {sbom_attestation_path}")
    except subprocess.CalledProcessError as e:
        audit_trail_event(audit_trail, "SBOM_ATTESTATION", {
            "status": "fail"
        })
        message = f"[!] Failed to attest SBOM for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Signature Fail"
        print(message)
        alert_event_system(audit_trail, message, alert, alert_path)
        alerts_list.append(f"{message}")

def sign_attest(audit_trail, alerts_list, cosign_key_path, cosign_pub_path, att_sig_path, sbom_attestation_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author):
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
        audit_trail_event(audit_trail, "SIGNING_ATTESTATION", {
            "status": "success"
        })
        print(f"[+] Attestation signed: {att_sig_path}")
    except subprocess.CalledProcessError as e:
        audit_trail_event(audit_trail, "SIGNING_ATTESTATION", {
            "status": "fail"
        })
        message = f"[!] Failed to sign Attestation for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Signature Fail"
        print(message)
        alert_event_system(audit_trail, message, alert, alert_path)
        alerts_list.append(f"{message}")
    
    try:
        subprocess.run(
            [
                "cosign", "verify-blob",
                "--key", cosign_pub_path,
                "--signature", att_sig_path,
                sbom_attestation_path
            ],
            check=True,
            env=env
        )
        syft_attestation_verified = True
        message = f"[+] Verified Attestation signature for repo: {repo_name}"
        audit_trail_event(audit_trail, "VERIFY_SIGNATURE_ATTESTATION", {
            "status": "success"
        })
        print(f"{message}")
        return syft_attestation_verified
    except subprocess.CalledProcessError:
        syft_attestation_verified = False
        message = f"[!] Signature for Attestation failed for repo: {repo_name}!"
        alert = "Scheduled Event : Signature Fail"
        audit_trail_event(audit_trail, "VERIFY_SIGNATURE_ATTESTATION", {
            "status": "fail"
        })
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
        alerts_list.append(f"{message}")
        return syft_attestation_verified

def key_generating(audit_trail, alerts_list, repo_name, scan_dir, cosign_key_path, cosign_pub_path, alert_path):
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
        audit_trail_event(audit_trail, "KEY_GENERATION", {
            "status": "success"
        })
        print(f"[+] Cosign key generated for repo: {repo_name}")

    except subprocess.CalledProcessError as e:
        message = f"[!] Failed to generate Cosign key for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Signature Fail"
        audit_trail_event(audit_trail, "KEY_GENERATION", {
            "status": "fail"
        })
        print(message)
        alert_event_system(audit_trail, message, alert, alert_path)
        if alerts_list is not False:
            alerts_list.append(f"{message}")

def sign_image(audit_trail, cosign_key_path, image_sig_path, image_digest_path, repo_name, alert_path):
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
        audit_trail_event(audit_trail, "IMAGE_SIGNING", {
            "status": "success"
        })
        result = "image signed"
        status_code = 200
        return result, status_code
    except subprocess.CalledProcessError as e:
        message = f"[!] Failed to sign image for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Signature Fail"
        audit_trail_event(audit_trail, "IMAGE_SIGNING", {
            "status": "fail"
        })
        print(message)
        alert_event_system(audit_trail, message, alert, alert_path)
        result = "image signing failed"
        status_code = 500
        return result, status_code

def verify_image(audit_trail, cosign_pub_path, image_sig_path, image_digest_path_verify, repo_name, alert_path):
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
        audit_trail_event(audit_trail, "IMAGE_SIGNING_VERIFY", {
            "status": "success"
        })
        verify_image_status = jsonify({"verify_image_status": "image verified and is trusted"}), 200
        return verify_image_status
    except subprocess.CalledProcessError as e:
        message = f"[!] Failed to verify image for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Verification Fail"
        audit_trail_event(audit_trail, "IMAGE_SIGNING_VERIFY", {
            "status": "fail"
        })
        print(message)
        alert_event_system(audit_trail, message, alert, alert_path)
        verify_image_status = jsonify({"verify_image_status": "image verification mismatch and is not trusted"}), 422
        return verify_image_status