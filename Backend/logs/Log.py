import os
import json
from filelock import FileLock

def log_event(repo_dir, repo_name, timestamp, event, commit_sha, commit_author):
    
    log_path = os.path.join(repo_dir, f"{repo_name}_event_log.json")
    lock_path = log_path + ".lock"
    lock = FileLock(lock_path)

    with lock:
        logs = []
        if os.path.exists(log_path):
            try:
                with open(log_path, "r") as f:
                    data = f.read().strip()
                    if data:
                        logs = json.loads(data)
            except json.JSONDecodeError:
                print(f"[!] JSON decode error in log file.")

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