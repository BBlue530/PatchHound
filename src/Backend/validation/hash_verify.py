import os
import json
from utils.file_hash import hash_file
from logs.audit_trail import audit_trail_event
from logs.alerts import alert_event_system

def verify_sha(audit_trail, repo_path, timestamp_folder, repo_name, alert_path):
    scan_dir = os.path.join(repo_path, timestamp_folder)

    repo_history_path = os.path.join(repo_path, f"{repo_name}_repo_history.json")
    sbom_path = os.path.join(scan_dir, f"{repo_name}_sbom_cyclonedx.json")
    sbom_attestation_path = f"{sbom_path}.att"
    audit_trail_path = os.path.join(scan_dir, f"{repo_name}_audit_trail.json")

    sbom_att_hash_new = hash_file(sbom_attestation_path)
    sbom_hash_new = hash_file(sbom_path)
    audit_trail_hash_new = hash_file(audit_trail_path)

    with open(repo_history_path, "r") as f:
        history_data = json.load(f)

    old_entry = None
    for entry in history_data["history"]:
        if str(timestamp_folder) in entry:
            old_entry = entry[timestamp_folder]
            break

    if old_entry is None:
        print(f"[!] No history entry found for: {repo_name} {timestamp_folder}")
        audit_trail_event(audit_trail, "HASH_VERIFY", {
        "status": "fail",
        "reason": f"no history entry found for: {timestamp_folder}"
        })
        message = f"[!] No history entry found for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
        return

    sbom_att_hash_old = old_entry["attestation"]["hash"]
    sbom_hash_old = old_entry["sbom_hash"]
    audit_trail_hash_old = old_entry["audit_trail_hash"]

    if sbom_att_hash_new != sbom_att_hash_old:
        audit_trail_event(audit_trail, "HASH_VERIFY", {
        "status": "fail",
        "reason": f"attestation hash mismatch for: {timestamp_folder}"
        })
        message = f"[!] Attestation hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
    elif sbom_hash_new != sbom_hash_old:
        audit_trail_event(audit_trail, "HASH_VERIFY", {
        "status": "fail",
        "reason": f"sbom hash mismatch for: {timestamp_folder}"
        })
        message = f"[!] SBOM hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
    elif audit_trail_hash_new != audit_trail_hash_old:
        audit_trail_event(audit_trail, "HASH_VERIFY", {
        "status": "fail",
        "reason": f"audit_trail hash mismatch for: {timestamp_folder}"
        })
        message = f"[!]  Audit trail hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
