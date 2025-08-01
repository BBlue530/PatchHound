import os
import time

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