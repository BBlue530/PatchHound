import json
import os
from utils.file_hash import hash_file
from external_storage.external_storage_append import append_to_external_storage
from logs.audit_trail import audit_trail_event
from logs.alerts import alert_event_system

def track_repo_history(audit_trail_hash, repo_history_path, timestamp, commit_sha, vulns_found, syft_sbom_attestation_path, syft_sbom_path, syft_attestation_verified, trivy_sbom_attestation_path, trivy_report_path, trivy_attestation_verified, summary_report_path, alerts_list):
    syft_sbom_att_hash = hash_file(syft_sbom_attestation_path)
    syft_sbom_hash = hash_file(syft_sbom_path)

    trivy_sbom_att_hash = hash_file(trivy_sbom_attestation_path)
    trivy_sbom_hash = hash_file(trivy_report_path)
    summary_report_hash = hash_file(summary_report_path)

    new_entry = {
        str(timestamp): {
        "commit_sha": commit_sha,
        "timestamp": timestamp,
        "syft_sbom_hash": syft_sbom_hash,
        "trivy_sbom_hash": trivy_sbom_hash,
        "audit_trail_hash": audit_trail_hash,
        "summary_report_hash": summary_report_hash,
        "vulnerabilities": vulns_found,
        "attestation": {
            "syft_sbom_att_hash": syft_sbom_att_hash,
            "syft_attestation_verified": syft_attestation_verified,
            "trivy_sbom_att_hash": trivy_sbom_att_hash,
            "trivy_attestation_verified": trivy_attestation_verified
        },
        "alerts": alerts_list
        }
    }

    if os.environ.get("external_storage_enabled", "False").lower() == "true":
        append_to_external_storage(new_entry, repo_history_path)
    else:
        print("[+] AWS s3 not enabled.")
        if os.path.exists(repo_history_path):
            with open(repo_history_path, "r") as f:
                history_data = json.load(f)
        else:
            history_data = []

        history_data.append(new_entry)

        with open(repo_history_path, "w") as f:
            json.dump(history_data, f, indent=4)

        print(f"[+] History updated: {repo_history_path}")

def update_repo_history(audit_trail, repo_name, alert_path, summary_report_path, repo_history_path, timestamp_folder):
    summary_report_hash_updated = hash_file(summary_report_path)

    with open(repo_history_path, "r") as f:
        repo_history = json.load(f)

    timestamp_repo_history_entry = repo_history[timestamp_folder]

    if timestamp_repo_history_entry:
        timestamp_repo_history_entry["summary_report_hash"] = summary_report_hash_updated

        with open(repo_history_path, "w") as f:
            json.dump(repo_history, f, indent=2)
    else:
        audit_trail_event(audit_trail, "HASH_UPDATE", {
        "status": "fail",
        "reason": f"summary_report_hash hash failed to update for: {timestamp_folder}"
        })
        message = f"[!]  Summary report hash failed to update for repo: {repo_name} Timestamp: {timestamp_folder}! No such entry exist repo history!"
        alert = "Scheduled Event : Internal Error"
        print(f"{message}")
        alert_event_system(audit_trail, message, alert, alert_path)