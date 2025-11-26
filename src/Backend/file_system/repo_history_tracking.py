import json
import os
from utils.file_hash import hash_file

def track_repo_history(audit_trail_hash, repo_history_path, timestamp, commit_sha, vulns_found, syft_sbom_attestation_path, syft_sbom_path, syft_attestation_verified, trivy_sbom_attestation_path, trivy_report_path, trivy_attestation_verified, alerts_list):
    syft_sbom_att_hash = hash_file(syft_sbom_attestation_path)
    syft_sbom_hash = hash_file(syft_sbom_path)

    trivy_sbom_att_hash = hash_file(trivy_sbom_attestation_path)
    trivy_sbom_hash = hash_file(trivy_report_path)

    new_entry = {
        str(timestamp): {
        "commit_sha": commit_sha,
        "timestamp": timestamp,
        "syft_sbom_hash": syft_sbom_hash,
        "trivy_sbom_hash": trivy_sbom_hash,
        "audit_trail_hash": audit_trail_hash,
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

    if not os.path.exists(repo_history_path):
        history_data = {"repo": os.path.basename(os.path.dirname(repo_history_path)), "history": []}
    else:
        with open(repo_history_path, "r") as f:
            history_data = json.load(f)

    history_data["history"].append(new_entry)

    with open(repo_history_path, "w") as f:
        json.dump(history_data, f, indent=4)

    print(f"[+] History updated: {repo_history_path}")