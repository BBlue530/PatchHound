import json
import os
from utils.file_hash import hash_file

def track_repo_history(audit_trail_hash, repo_history_path, timestamp, commit_sha, vulns_found, sbom_attestation_path, sbom_path, attestation_verified, alerts_list):
    sbom_att_hash = hash_file(sbom_attestation_path)
    sbom_hash = hash_file(sbom_path)
    new_entry = {
        "commit_sha": commit_sha,
        "timestamp": timestamp,
        "sbom_hash": sbom_hash,
        "audit_trail_hash": audit_trail_hash,
        "vulnerabilities": vulns_found,
        "attestation": {
            "hash": sbom_att_hash,
            "signature_valid": attestation_verified
        },
        "alerts": alerts_list
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