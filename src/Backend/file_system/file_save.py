from flask import jsonify, request
import json
import os
import subprocess
import json
import tempfile
from core.variables import env
from alerts.alerts import alert_event_system
from utils.helpers import file_stable_check
from external_storage.external_storage_get import get_resources_external_storage_internal_use
from external_storage.external_storage_send import send_files_to_external_storage
from utils.secrets_manager import read_secret
from logs.event_handler import event
from core.variables import local_bin, log_type_info, log_type_debug, log_type_error, log_message_key, log_level_key, log_module_key, log_details_key

def save_files(audit_trail, grype_path, grype_vulns_cyclonedx_json_data, prio_path, prio_vuln_data, alert_path, alert_system_json, syft_sbom_path, syft_sbom_json, semgrep_sast_report_path, semgrep_sast_report_json, trivy_report_path, trivy_report_json, fail_on_severity_json, fail_on_severity_path):
    file_save_status = True
    files_failed_save = []

    if alert_system_json:
        save_file(alert_path, alert_system_json)
    else:
        files_failed_save.append("alert_system")
        file_save_status = False
        event(audit_trail, {
            log_message_key: "alert system failed to save",
            log_level_key: log_type_error,
            log_module_key: "save_files",
            log_details_key: {
                "alert_system": alert_path,
            }
        })

    if syft_sbom_json:
        save_file(syft_sbom_path, syft_sbom_json)
    else:
        files_failed_save.append("syft_sbom")
        file_save_status = False
        event(audit_trail, {
            log_message_key: "sbom failed to save",
            log_level_key: log_type_error,
            log_module_key: "save_files",
            log_details_key: {
                "syft_sbom": syft_sbom_path,
            }
        })
    
    if semgrep_sast_report_json:
        save_file(semgrep_sast_report_path, semgrep_sast_report_json)
    else:
        files_failed_save.append("semgrep_sast_report")
        file_save_status = False
        event(audit_trail, {
            log_message_key: "semgrep report failed to save",
            log_level_key: log_type_error,
            log_module_key: "save_files",
            log_details_key: {
                "semgrep_sast_report": semgrep_sast_report_path,
            }
        })

    if trivy_report_json:
        save_file(trivy_report_path, trivy_report_json)
    else:
        files_failed_save.append("trivy_report")
        file_save_status = False
        event(audit_trail, {
            log_message_key: "trivy report failed to save",
            log_level_key: log_type_error,
            log_module_key: "save_files",
            log_details_key: {
                "trivy_report": trivy_report_path,
            }
        })

    if grype_vulns_cyclonedx_json_data:
        save_file(grype_path, grype_vulns_cyclonedx_json_data)
    else:
        files_failed_save.append("grype_vulns_cyclonedx")
        file_save_status = False
        event(audit_trail, {
            log_message_key: "grype vulnerability report failed to save",
            log_level_key: log_type_error,
            log_module_key: "save_files",
            log_details_key: {
                "grype_vulns_cyclonedx": grype_path,
            }
        })

    if prio_vuln_data:
        save_file(prio_path, prio_vuln_data)
    else:
        files_failed_save.append("prio_vuln_data")
        file_save_status = False
        event(audit_trail, {
            log_message_key: "prio vulnerabilities report failed to save",
            log_level_key: log_type_error,
            log_module_key: "save_files",
            log_details_key: {
                "pyio_vuln_data": prio_path,
            }
        })

    if fail_on_severity_json:
        save_file(fail_on_severity_path, fail_on_severity_json)
    else:
        files_failed_save.append("fail_on_severity")
        file_save_status = False
        event(audit_trail, {
            log_message_key: "fail on severity failed to save",
            log_level_key: log_type_error,
            log_module_key: "save_files",
            log_details_key: {
                "fail_on_severity": fail_on_severity_path,
            }
        })

    if file_save_status:
        event(audit_trail, {
            log_message_key: "all files saved",
            log_level_key: log_type_info,
            log_module_key: "save_files",
            log_details_key: {
                "": ""
            }
        })

    else:
        message = f"[!] Failed to save files!"
        alert = "Workflow : Failed to save files"
        event(audit_trail, {
            log_message_key: "failed to save files and reports",
            log_level_key: log_type_error,
            log_module_key: "save_files",
            log_details_key: {
                "": ""
            }
        })
        alert_event_system(audit_trail, message, alert, alert_path)

def save_file(file_path, file_json):
    with open(file_path, "w") as f:
        json.dump(file_json, f, indent=4)
    file_stable_check(file_path)

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
        event(audit_trail, {
            log_message_key: "sbom attested",
            log_level_key: log_type_debug,
            log_module_key: "attest_sbom",
            log_details_key: {
                "repo_dir": repo_dir,
                "timestamp": timestamp,
                "commit_sha": commit_sha,
                "commit_author": commit_author
            }
        })

    except subprocess.CalledProcessError as e:
        event(audit_trail, {
            log_message_key: "failed to attest sbom",
            log_level_key: log_type_error,
            log_module_key: "attest_sbom",
            log_details_key: {
                "error": str(e),
                "repo_dir": repo_dir,
                "timestamp": timestamp,
                "commit_sha": commit_sha,
                "commit_author": commit_author
            }
        })
        message = f"[!] Failed to attest SBOM for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Signature Fail"
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
        event(audit_trail, {
            log_message_key: "attestation signed",
            log_level_key: log_type_debug,
            log_module_key: "attest_sbom",
            log_details_key: {
                "repo_dir": repo_dir,
                "timestamp": timestamp,
                "commit_sha": commit_sha,
                "commit_author": commit_author
            }
        })
        print(f"[+] Attestation signed: {att_sig_path}")
    except subprocess.CalledProcessError as e:
        event(audit_trail, {
            log_message_key: "signing attestation failed",
            log_level_key: log_type_error,
            log_module_key: "attest_sbom",
            log_details_key: {
                "error": str(e),
                "repo_dir": repo_dir,
                "timestamp": timestamp,
                "commit_sha": commit_sha,
                "commit_author": commit_author
            }
        })
        message = f"[!] Failed to sign Attestation for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Signature Fail"
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
        event(audit_trail, {
            log_message_key: "attestation signature verified",
            log_level_key: log_type_debug,
            log_module_key: "attest_sbom",
            log_details_key: {
                "repo_dir": repo_dir,
                "timestamp": timestamp,
                "commit_sha": commit_sha,
                "commit_author": commit_author
            }
        })
        return syft_attestation_verified

    except subprocess.CalledProcessError:
        syft_attestation_verified = False
        message = f"[!] Signature for Attestation failed for repo: {repo_name}!"
        alert = "Scheduled Event : Signature Fail"
        event(audit_trail, {
            log_message_key: "",
            log_level_key: log_type_error,
            log_module_key: "attest_sbom",
            log_details_key: {
                "error": str(e),
                "repo_dir": repo_dir,
                "timestamp": timestamp,
                "commit_sha": commit_sha,
                "commit_author": commit_author
            }
        })
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
        event(audit_trail, {
            log_message_key: "cosign signature keys generated",
            log_level_key: log_type_debug,
            log_module_key: "key_generating",
            log_details_key: {
                "repo_name": repo_name
            }
        })

    except subprocess.CalledProcessError as e:
        message = f"[!] Failed to generate Cosign key for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Signature Fail"
        event(audit_trail, {
            log_message_key: "failed to generate cosign keys",
            log_level_key: log_type_error,
            log_module_key: "key_generating",
            log_details_key: {
                "error": str(e),
                "repo_name": repo_name
            }
        })
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
        event(audit_trail, {
            log_message_key: "image signed",
            log_level_key: log_type_debug,
            log_module_key: "sign_image",
            log_details_key: {
                "repo_name": repo_name
            }
        })
        result = "image signed"
        status_code = 200
        return result, status_code

    except subprocess.CalledProcessError as e:
        message = f"[!] Failed to sign image for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Signature Fail"
        event(audit_trail, {
            log_message_key: "failed to sign image",
            log_level_key: log_type_error,
            log_module_key: "sign_image",
            log_details_key: {
                "error": str(e),
                "repo_name": repo_name
            }
        })
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
        event(audit_trail, {
            log_message_key: "image verified",
            log_level_key: log_type_debug,
            log_module_key: "verify_image",
            log_details_key: {
                "repo_name": repo_name
            }
        })
        verify_image_status = jsonify({"verify_image_status": "image verified and is trusted"}), 200
        return verify_image_status

    except subprocess.CalledProcessError as e:
        message = f"[!] Failed to verify image for repo: {repo_name} {e.stderr}!"
        alert = "Workflow : Verification Fail"
        event(audit_trail, {
            log_message_key: "failed to verifiy image signature",
            log_level_key: log_type_error,
            log_module_key: "verify_image",
            log_details_key: {
                "error": str(e),
                "repo_name": repo_name
            }
        })
        alert_event_system(audit_trail, message, alert, alert_path)
        verify_image_status = jsonify({"verify_image_status": "image verification mismatch and is not trusted"}), 422
        return verify_image_status
    
def sign_file(cosign_key_path, cosign_pub_path, file_sig_path, file_filename_path, repo_name, s3_bucket_dir):
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

            with open(cosign_pub_path, "wb") as f:
                f.write(cosign_key_pub_bytes)
            print(f"[+] Wrote public key to disk: {cosign_pub_path}")
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
            send_files_to_external_storage(file_sig_path, s3_bucket_dir)
            send_files_to_external_storage(file_filename_path, s3_bucket_dir)
    
    except subprocess.CalledProcessError as e:
        event(False, {
            log_message_key: "signature or verification failed for repo",
            log_level_key: log_type_error,
            log_module_key: "generate_pdf",
            log_details_key: {
                "repo_name": repo_name,
                "error": e.stderr
            }
        })

    finally:
        for f in temp_files:
            try:
                os.unlink(f)
            except Exception:
                pass