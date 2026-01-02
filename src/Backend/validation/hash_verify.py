import os
import json
from utils.file_hash import hash_file
from logs.audit_trail import audit_trail_event
from logs.alerts import alert_event_system

def verify_sha(audit_trail, repo_path, timestamp_folder, repo_name, alert_path):
    scan_dir = os.path.join(repo_path, timestamp_folder)

    repo_history_path = os.path.join(repo_path, f"{repo_name}_repo_history.json")
    audit_trail_path = os.path.join(scan_dir, f"{repo_name}_audit_trail.json")
    summary_report_path = os.path.join(scan_dir, f"{repo_name}_summary_report.json")

    syft_sbom_path = os.path.join(scan_dir, f"{repo_name}_syft_sbom_cyclonedx.json")
    syft_sbom_attestation_path = f"{syft_sbom_path}.att"

    trivy_report_path = os.path.join(scan_dir, f"{repo_name}_trivy_report.json")
    trivy_sbom_attestation_path = f"{trivy_report_path}.att"

    syft_sbom_att_hash_new = hash_file(syft_sbom_attestation_path)
    syft_sbom_hash_new = hash_file(syft_sbom_path)

    trivy_sbom_att_hash_new = hash_file(trivy_sbom_attestation_path)
    trivy_sbom_hash_new = hash_file(trivy_report_path)

    audit_trail_hash_new = hash_file(audit_trail_path)
    summary_report_hash_new = hash_file(summary_report_path)

    with open(repo_history_path, "r") as f:
        repo_history = json.load(f)

    history_data = repo_history.get("history", [])

    old_entry = None
    for entry in history_data:
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

    syft_sbom_att_hash_old = old_entry["attestation"]["syft_sbom_att_hash"]
    syft_sbom_hash_old = old_entry["syft_sbom_hash"]

    trivy_sbom_att_hash_old = old_entry["attestation"]["trivy_sbom_att_hash"]
    trivy_sbom_hash_old = old_entry["trivy_sbom_hash"]

    audit_trail_hash_old = old_entry["audit_trail_hash"]
    summary_report_hash_old = old_entry["summary_report_hash"]

    # Syft checks
    if syft_sbom_att_hash_new != syft_sbom_att_hash_old:
        audit_trail_event(audit_trail, "SYFT_HASH_VERIFY", {
        "status": "fail",
        "reason": f"attestation hash mismatch for: {timestamp_folder}"
        })
        message = f"[!] SYFT_Attestation hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
    if syft_sbom_hash_new != syft_sbom_hash_old:
        audit_trail_event(audit_trail, "SYFT_HASH_VERIFY", {
        "status": "fail",
        "reason": f"sbom hash mismatch for: {timestamp_folder}"
        })
        message = f"[!] SYFT_SBOM hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
    
    # Trivy checks
    if trivy_sbom_att_hash_new != trivy_sbom_att_hash_old:
        audit_trail_event(audit_trail, "TRIVY_HASH_VERIFY", {
        "status": "fail",
        "reason": f"attestation hash mismatch for: {timestamp_folder}"
        })
        message = f"[!] TRIVY_Attestation hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
    if trivy_sbom_hash_new != trivy_sbom_hash_old:
        audit_trail_event(audit_trail, "TRIVY_HASH_VERIFY", {
        "status": "fail",
        "reason": f"sbom hash mismatch for: {timestamp_folder}"
        })
        message = f"[!] TRIVY_SBOM hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)

    # Audit trail check
    if audit_trail_hash_new != audit_trail_hash_old:
        audit_trail_event(audit_trail, "HASH_VERIFY", {
        "status": "fail",
        "reason": f"audit_trail hash mismatch for: {timestamp_folder}"
        })
        message = f"[!]  Audit trail hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)

    # Summary report check
    if summary_report_hash_new != summary_report_hash_old:
        audit_trail_event(audit_trail, "HASH_VERIFY", {
        "status": "fail",
        "reason": f"summary_report_hash hash mismatch for: {timestamp_folder}"
        })
        message = f"[!]  Summary report hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)
