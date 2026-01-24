import os
import time
import json
import html

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
    cve_ids = set()

    for vuln in vuln_data.get("vulnerabilities", []):
        cve_id = vuln.get("id")
        if cve_id:
            cve_ids.add(cve_id)

    return cve_ids

def extract_kev_cve_ids(vuln_data):
    kev_cve_ids = set()

    prioritized = vuln_data.get("prioritized_vulns", {})

    for vuln_list in prioritized.values():
        for vuln in vuln_list:
            cve_id = vuln.get("cveID")
            if cve_id:
                kev_cve_ids.add(cve_id)

    return kev_cve_ids

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
    return html.escape(str(value), quote=False)

def load_file_data(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            file_data = json.load(f)
        return file_data
    return {}