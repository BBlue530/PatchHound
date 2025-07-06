import os
import json

def log_event(repo_dir, repo_name, timestamp, event, commit_sha, commit_author):
    
    log_path = os.path.join(repo_dir, f"{repo_name}_event_log.json")

    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []
    else:
        logs = []

    log_entry = {
        "log_id": len(logs) + 1,
        "timestamp": timestamp,
        "event": event,
        "commit_sha": commit_sha,
        "commit_author": commit_author
    }

    logs.append(log_entry)

    with open(log_path, "w") as f:
        json.dump(logs, f, indent=4)