import os
import tempfile
from utils.helpers import file_stable_check
from file_system.file_save import sign_image, verify_image, key_generating
from validation.secrets_manager import read_secret
from core.variables import all_repo_scans_folder, local_bin, env

def sign_image_digest(image_digest, organization, current_repo, timestamp, commit_sha, commit_author):
    print("[~] Signing image...")
    secret_type = "cosign_key"
    cosign_key = read_secret(secret_type)

    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")
    env["COSIGN_PASSWORD"] = cosign_key

    repo_name = current_repo.replace("/", "_")
    scan_dir = os.path.join(all_repo_scans_folder, organization, repo_name, timestamp)
    repo_dir = os.path.join(all_repo_scans_folder, organization, repo_name)
    image_digest_path = os.path.join(scan_dir, f"{repo_name}_image_digest.txt")
    alert_path = os.path.join(repo_dir, f"{repo_name}_alert.json")
    cosign_key_path = os.path.join(scan_dir, f"{repo_name}.key")
    cosign_pub_path = os.path.join(scan_dir, f"{repo_name}.pub")
    image_sig_path = os.path.join(scan_dir, f"{repo_name}_image.sig")

    os.makedirs(scan_dir, exist_ok=True)

    if not (os.path.exists(cosign_key_path) and os.path.exists(cosign_pub_path)):
        key_generating(repo_name, scan_dir, cosign_key_path, cosign_pub_path, alert_path, repo_dir, timestamp, commit_sha, commit_author)

    with open(image_digest_path, "w") as f:
        f.write(image_digest)
    file_stable_check(image_digest_path)

    sign_image(cosign_key_path, image_sig_path, image_digest_path, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)

def verify_image_digest(image_digest, organization, current_repo, timestamp, commit_sha, commit_author):
    print("[~] Verifying image...")
    repo_name = current_repo.replace("/", "_")
    scan_dir = os.path.join(all_repo_scans_folder, organization, repo_name, timestamp)
    repo_dir = os.path.join(all_repo_scans_folder, organization, repo_name)
    alert_path = os.path.join(repo_dir, f"{repo_name}_alert.json")
    cosign_pub_path = os.path.join(scan_dir, f"{repo_name}.pub")
    image_sig_path = os.path.join(scan_dir, f"{repo_name}_image.sig")

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
        temp_file.write(image_digest)
        temp_file.flush()
        image_digest_path_verify = temp_file.name

    os.makedirs(scan_dir, exist_ok=True)

    verify_image_status = verify_image(cosign_pub_path, image_sig_path, image_digest_path_verify, repo_name, alert_path, repo_dir, timestamp, commit_sha, commit_author)

    os.remove(image_digest_path_verify)

    return verify_image_status