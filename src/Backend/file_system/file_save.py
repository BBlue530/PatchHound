from flask import jsonify
import json
import os
import subprocess
import json
import tempfile
from core.variables import env
from logs.alerts import alert_event_system
from utils.helpers import file_stable_check
from logs.audit_trail import audit_trail_event
from external_storage.external_storage_get import get_resources_external_storage_internal_use
from external_storage.external_storage_send import send_files_to_external_storage
from validation.secrets_manager import read_secret
from core.variables import local_bin

def save_files(audit_trail, grype_path, grype_vulns_cyclonedx_json_data, prio_path, prio_vuln_data, alert_path, alert_system_json, syft_sbom_path, syft_sbom_json, semgrep_sast_report_path, semgrep_sast_report_json, trivy_report_path, trivy_report_json, summary_report_path, summary_report, exclusions_file_path, exclusions_file_json):
    file_save_status = True
    files_failed_save = []

    if alert_system_json:
        with open(alert_path, "w") as f:
            json.dump(alert_system_json, f, indent=4)
        file_stable_check(alert_path)
    else:
        files_failed_save.append("alert_system")
        file_save_status = False
        audit_trail_event(audit_trail, "FILE_SAVE", {
            "alert_system": alert_path,
            "status": "fail"
        })

    if syft_sbom_json:
        with open(syft_sbom_path, "w") as f:
            json.dump(syft_sbom_json, f, indent=4)
        file_stable_check(syft_sbom_path)
    else:
        files_failed_save.append("syft_sbom")
        file_save_status = False
        audit_trail_event(audit_trail, "FILE_SAVE", {
            "syft_sbom": syft_sbom_path,
            "status": "fail"
        })
    
    if semgrep_sast_report_json:
        with open(semgrep_sast_report_path, "w") as f:
            json.dump(semgrep_sast_report_json, f, indent=4)
        file_stable_check(semgrep_sast_report_path)
    else:
        files_failed_save.append("semgrep_sast_report")
        file_save_status = False
        audit_trail_event(audit_trail, "FILE_SAVE", {
            "semgrep_sast_report": semgrep_sast_report_path,
            "status": "fail"
        })

    if trivy_report_json:
        with open(trivy_report_path, "w") as f:
            json.dump(trivy_report_json, f, indent=4)
        file_stable_check(trivy_report_path)
    else:
        files_failed_save.append("trivy_report")
        file_save_status = False
        audit_trail_event(audit_trail, "FILE_SAVE", {
            "trivy_report": trivy_report_path,
            "status": "fail"
        })

    if grype_vulns_cyclonedx_json_data:
        with open(grype_path, "w") as f:
            json.dump(grype_vulns_cyclonedx_json_data, f, indent=4)
        file_stable_check(grype_path)
    else:
        files_failed_save.append("grype_vulns_cyclonedx")
        file_save_status = False
        audit_trail_event(audit_trail, "FILE_SAVE", {
            "grype_vulns_cyclonedx": grype_path,
            "status": "fail"
        })

    if prio_vuln_data:
        with open(prio_path, "w") as f:
            json.dump(prio_vuln_data, f, indent=4)
        file_stable_check(prio_path)
    else:
        files_failed_save.append("prio_vuln_data")
        file_save_status = False
        audit_trail_event(audit_trail, "FILE_SAVE", {
            "pyio_vuln_data": prio_path,
            "status": "fail"
        })

    if summary_report:
        with open(summary_report_path, "w") as f:
            json.dump(summary_report, f, indent=4)
        file_stable_check(summary_report_path)
    else:
        files_failed_save.append("summary_report")
        file_save_status = False
        audit_trail_event(audit_trail, "FILE_SAVE", {
            "summary_report": summary_report_path,
            "status": "fail"
        })

    if exclusions_file_json:
        with open(exclusions_file_path, "w") as f:
            json.dump(exclusions_file_json, f, indent=4)
        file_stable_check(exclusions_file_path)
    else:
        files_failed_save.append("exclusions_file")
        file_save_status = False
        audit_trail_event(audit_trail, "FILE_SAVE", {
            "exclusion_file": exclusions_file_path,
            "status": "fail"
        })
    if file_save_status:
        audit_trail_event(audit_trail, "FILE_SAVE", {
                "status": "success"
            })
    else:
        message = f"[!] Failed to save files!"
        alert = "Workflow : Failed to save files"
        audit_trail_event(audit_trail, "KEY_GENERATION", {
            "status": "fail"
        })
        print(message)
        alert_event_system(audit_trail, message, alert, alert_path)

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
        # Its fine to have the priv key saved since its encrypted by the COSIGN_PASSWORD
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
        if alerts_list is not None:
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
    
def sign_file(cosign_key_path, cosign_pub_path, file_sig_path, file_filename_path, repo_name):
    print("[~] Signing file...")
    secret_type = "cosign_key"
    cosign_key = read_secret(secret_type)

    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")
    env["COSIGN_PASSWORD"] = cosign_key

    temp_files = []

    try:
        if os.environ.get("external_storage_enabled", "False").lower() == "true":
            cosign_key_priv_bytes = get_resources_external_storage_internal_use(cosign_key_path).read()
            cosign_key_pub_bytes = get_resources_external_storage_internal_use(cosign_pub_path).read()

            temp_priv = tempfile.NamedTemporaryFile(delete=False)
            temp_priv.write(cosign_key_priv_bytes)
            temp_priv.flush()
            temp_files.append(temp_priv.name)

            temp_pub = tempfile.NamedTemporaryFile(delete=False)
            temp_pub.write(cosign_key_pub_bytes)
            temp_pub.flush()
            temp_files.append(temp_pub.name)

            cosign_key_priv = temp_priv.name
            cosign_key_pub = temp_pub.name
        else:
            cosign_key_priv = cosign_key_path
            cosign_key_pub = cosign_pub_path
        subprocess.run(
            [
                "cosign", "sign-blob",
                "-y",
                "--key", cosign_key_priv,
                "--output-signature", file_sig_path,
                file_filename_path
            ],
            check=True,
            env=env
        )
        print(f"[+] File signed: {file_sig_path}")
    
        subprocess.run(
            [
                "cosign", "verify-blob",
                "--key", cosign_key_pub,
                "--signature", file_sig_path,
                file_filename_path
            ],
            check=True,
            env=env
        )
        print(f"[+] Verified file signature for repo: {repo_name}")

        if os.environ.get("external_storage_enabled", "False").lower() == "true":
            # Any files that gets signed will be sent to external storage. Might change it later on...
            send_files_to_external_storage(file_sig_path, file_sig_path)
            send_files_to_external_storage(file_filename_path, file_filename_path)
    
    except subprocess.CalledProcessError as e:
        print(f"[!] Signing or verification failed for repo {repo_name}: {e.stderr}")

    finally:
        for f in temp_files:
            try:
                os.unlink(f)
            except Exception:
                pass