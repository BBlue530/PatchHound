import os
from utils.helpers import load_file_data
from utils.file_hash import hash_file
from alerts.alerts import alert_event_system
from logs.event_handler import event
from core.variables import *

def verify_sha(audit_trail, repo_path, timestamp_folder, repo_name, alert_path):
    scan_dir = os.path.join(repo_path, timestamp_folder)

    repo_history_path = os.path.join(repo_path, f"{repo_name}{repo_history_path_ending}")
    audit_trail_path = os.path.join(scan_dir, f"{repo_name}{audit_trail_path_ending}")
    summary_report_path = os.path.join(scan_dir, f"{repo_name}{summary_report_path_ending}")

    syft_sbom_path = os.path.join(scan_dir, f"{repo_name}{syft_sbom_path_ending}")
    syft_sbom_attestation_path = f"{syft_sbom_path}{attestation_path_ending}"

    trivy_report_path = os.path.join(scan_dir, f"{repo_name}{trivy_report_path_ending}")
    trivy_sbom_attestation_path = f"{trivy_report_path}{attestation_path_ending}"

    syft_sbom_att_hash_new = hash_file(syft_sbom_attestation_path)
    syft_sbom_hash_new = hash_file(syft_sbom_path)

    trivy_sbom_att_hash_new = hash_file(trivy_sbom_attestation_path)
    trivy_sbom_hash_new = hash_file(trivy_report_path)

    audit_trail_hash_new = hash_file(audit_trail_path)
    summary_report_hash_new = hash_file(summary_report_path)

    history_data = load_file_data(repo_history_path)

    old_entry = None
    for entry in history_data:
        if str(timestamp_folder) in entry:
            old_entry = entry[timestamp_folder]
            break

    if old_entry is None:
        event(audit_trail, {
            log_message_key: "no history entry found",
            log_level_key: log_type_error,
            log_module_key: "verify_sha",
            log_details_key: {
                "repo_name": repo_name,
                "timestamp_folder": timestamp_folder
            }
        })
        message = f"[!] No history entry found for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
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
        event(audit_trail, {
            log_message_key: "attestation hash mismatch",
            log_level_key: log_type_error,
            log_module_key: "verify_sha",
            log_details_key: {
                "repo_name": repo_name,
                "timestamp_folder": timestamp_folder
            }
        })
        message = f"[!] SYFT_Attestation hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        alert_event_system(audit_trail, message, alert, alert_path)
    if syft_sbom_hash_new != syft_sbom_hash_old:
        event(audit_trail, {
            log_message_key: "sbom hash mismatch",
            log_level_key: log_type_error,
            log_module_key: "verify_sha",
            log_details_key: {
                "repo_name": repo_name,
                "timestamp_folder": timestamp_folder
            }
        })
        message = f"[!] SYFT_SBOM hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        alert_event_system(audit_trail, message, alert, alert_path)
    
    # Trivy checks
    if trivy_sbom_att_hash_new != trivy_sbom_att_hash_old:
        event(audit_trail, {
            log_message_key: "trivy attestation hash mismatch",
            log_level_key: log_type_error,
            log_module_key: "verify_sha",
            log_details_key: {
                "repo_name": repo_name,
                "timestamp_folder": timestamp_folder
            }
        })
        message = f"[!] TRIVY_Attestation hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        alert_event_system(audit_trail, message, alert, alert_path)
    if trivy_sbom_hash_new != trivy_sbom_hash_old:
        event(audit_trail, {
            log_message_key: "trivy sbom hash mismatch",
            log_level_key: log_type_error,
            log_module_key: "verify_sha",
            log_details_key: {
                "repo_name": repo_name,
                "timestamp_folder": timestamp_folder
            }
        })
        message = f"[!] TRIVY_SBOM hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        alert_event_system(audit_trail, message, alert, alert_path)

    # Audit trail check
    if audit_trail_hash_new != audit_trail_hash_old:
        event(audit_trail, {
            log_message_key: "audit trail hash mismatch",
            log_level_key: log_type_error,
            log_module_key: "verify_sha",
            log_details_key: {
                "repo_name": repo_name,
                "timestamp_folder": timestamp_folder
            }
        })
        message = f"[!] Audit trail hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        alert_event_system(audit_trail, message, alert, alert_path)

    # Summary report check
    if summary_report_hash_new != summary_report_hash_old:
        event(audit_trail, {
            log_message_key: "summary report hash mismatch",
            log_level_key: log_type_error,
            log_module_key: "verify_sha",
            log_details_key: {
                "repo_name": repo_name,
                "timestamp_folder": timestamp_folder
            }
        })
        message = f"[!]  Summary report hash mismatch for repo: {repo_name} Timestamp: {timestamp_folder}!"
        alert = "Scheduled Event : Tampering Detected"
        alert_event_system(audit_trail, message, alert, alert_path)
