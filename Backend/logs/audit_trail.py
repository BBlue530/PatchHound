import datetime
import json
import os
from utils.helpers import file_stable_check
from utils.file_hash import hash_file

def audit_trail_event(audit_trail, action, details=""):
    event = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "action": action,
        "details": details
    }
    audit_trail.append(event)
    return audit_trail

def save_audit_trail(audit_trail_path, audit_trail):
    with open(audit_trail_path, "w") as f:
        json.dump(audit_trail, f, indent=4)
    file_stable_check(audit_trail_path)
    audit_trail_hash = hash_file(audit_trail_path)
    return audit_trail_hash

def append_audit_trail(audit_trail_path, new_audit_event):
    if os.path.exists(audit_trail_path):
        with open(audit_trail_path, "r") as f:
            try:
                audit_trail = json.load(f)
            except json.JSONDecodeError:
                audit_trail = []
    else:
        audit_trail = []
    if isinstance(new_audit_event, dict):
        new_audit_event = [new_audit_event]
    audit_trail.extend(new_audit_event)
    with open(audit_trail_path, "w") as f:
        json.dump(audit_trail, f, indent=4)
    file_stable_check(audit_trail_path)