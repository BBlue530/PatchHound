import os
import time
import json

def file_stable_check(file_path, timeout=10):
    prev_size = -1
    for _ in range(timeout):
        if os.path.exists(file_path):
            curr_size = os.path.getsize(file_path)
            if curr_size == prev_size:
                return True
            prev_size = curr_size
        time.sleep(1)
    return False

def extract_cve_ids(vuln_data):
    return set(vuln.get("id") for vuln in vuln_data.get("vulnerabilities", []) if vuln.get("id"))

def load_json(file):
    if hasattr(file, 'read'):
        file.seek(0)
        file_json = json.load(file)
        return file_json
    elif isinstance(file, bytes):
       file_json = json.loads(file.decode('utf-8'))
       return file_json
    elif isinstance(file, str):
        file_json = json.loads(file)
        return file_json
    else:
        file_json = file
        return file_json

def safe_text(value):
    if value is None:
        return ""
    return str(value)