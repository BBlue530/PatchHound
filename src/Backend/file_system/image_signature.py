import os
import tempfile
from utils.helpers import file_stable_check
from file_system.file_save import sign_image, verify_image, key_generating
from validation.secrets_manager import read_secret
from logs.audit_trail import save_audit_trail, append_audit_log
from core.variables import all_image_signature_folder, local_bin, env, all_resources_folder, all_base_image_signature_folder

def sign_image_digest(audit_trail, image_digest, organization, current_repo, timestamp):
    print("[~] Signing image...")
    secret_type = "cosign_key"
    cosign_key = read_secret(secret_type)

    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")
    env["COSIGN_PASSWORD"] = cosign_key

    repo_name = current_repo.replace("/", "_")
    scan_dir = os.path.join(all_resources_folder, all_image_signature_folder, organization, repo_name, timestamp)
    repo_dir = os.path.join(all_resources_folder, all_image_signature_folder, organization, repo_name)
    image_digest_path = os.path.join(scan_dir, f"{repo_name}_image_digest.txt")
    alert_path = os.path.join(repo_dir, f"{repo_name}_alert.json")
    cosign_key_path = os.path.join(scan_dir, f"{repo_name}.key")
    cosign_pub_path = os.path.join(scan_dir, f"{repo_name}.pub")
    image_sig_path = os.path.join(scan_dir, f"{repo_name}_image.sig")
    audit_trail_path = os.path.join(scan_dir, f"{repo_name}_audit_trail.json")

    os.makedirs(scan_dir, exist_ok=True)

    alerts_list = False
    if not (os.path.exists(cosign_key_path) and os.path.exists(cosign_pub_path)):
        key_generating(audit_trail, alerts_list, repo_name, scan_dir, cosign_key_path, cosign_pub_path, alert_path)

    with open(image_digest_path, "w") as f:
        f.write(image_digest)
    file_stable_check(image_digest_path)

    result, status_code = sign_image(audit_trail, cosign_key_path, image_sig_path, image_digest_path, repo_name, alert_path)

    save_audit_trail(audit_trail_path, audit_trail)

    return result, status_code

def verify_image_digest(audit_trail, image_digest, organization, current_repo, timestamp):
    print("[~] Verifying image...")
    repo_name = current_repo.replace("/", "_")
    scan_dir = os.path.join(all_resources_folder, all_image_signature_folder, organization, repo_name, timestamp)
    repo_dir = os.path.join(all_resources_folder, all_image_signature_folder, organization, repo_name)
    alert_path = os.path.join(repo_dir, f"{repo_name}_alert.json")
    cosign_pub_path = os.path.join(scan_dir, f"{repo_name}.pub")
    image_sig_path = os.path.join(scan_dir, f"{repo_name}_image.sig")
    audit_trail_path = os.path.join(scan_dir, f"{repo_name}_audit_trail.json")

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
        temp_file.write(image_digest)
        temp_file.flush()
        image_digest_path_verify = temp_file.name

    os.makedirs(scan_dir, exist_ok=True)

    verify_image_status = verify_image(audit_trail, cosign_pub_path, image_sig_path, image_digest_path_verify, repo_name, alert_path)

    os.remove(image_digest_path_verify)

    append_audit_log(audit_trail_path, audit_trail)

    return verify_image_status

def sign_base_image_digest(audit_trail, image_digest, image_name):
    print("[~] Signing image...")
    secret_type = "cosign_key"
    cosign_key = read_secret(secret_type)

    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")
    env["COSIGN_PASSWORD"] = cosign_key

    image_dir = os.path.join(all_resources_folder, all_base_image_signature_folder, image_name)
    image_digest_path = os.path.join(image_dir, f"{image_name}_image_digest.txt")
    cosign_key_path = os.path.join(image_dir, f"{image_name}.key")
    cosign_pub_path = os.path.join(image_dir, f"{image_name}.pub")
    image_sig_path = os.path.join(image_dir, f"{image_name}_image.sig")
    audit_trail_path = os.path.join(image_dir, f"{image_name}_audit_trail.json")

    os.makedirs(image_dir, exist_ok=True)

    alerts_list = False
    if not (os.path.exists(cosign_key_path) and os.path.exists(cosign_pub_path)):
        key_generating(audit_trail, alerts_list, image_name, image_dir, cosign_key_path, cosign_pub_path, None)

    with open(image_digest_path, "w") as f:
        f.write(image_digest)
    file_stable_check(image_digest_path)

    result, status_code = sign_image(audit_trail, cosign_key_path, image_sig_path, image_digest_path, image_name, None)

    save_audit_trail(audit_trail_path, audit_trail)

    return result, status_code

def verify_base_image_digest(audit_trail, image_digest, image_name):
    print("[~] Verifying image...")
    image_dir = os.path.join(all_resources_folder, all_base_image_signature_folder, image_name)
    cosign_pub_path = os.path.join(image_dir, f"{image_name}.pub")
    image_sig_path = os.path.join(image_dir, f"{image_name}_image.sig")
    audit_trail_path = os.path.join(image_dir, f"{image_name}_audit_trail.json")

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
        temp_file.write(image_digest)
        temp_file.flush()
        image_digest_path_verify = temp_file.name

    os.makedirs(image_dir, exist_ok=True)

    verify_image_status = verify_image(audit_trail, cosign_pub_path, image_sig_path, image_digest_path_verify, image_name, None)

    os.remove(image_digest_path_verify)

    append_audit_log(audit_trail_path, audit_trail)

    return verify_image_status