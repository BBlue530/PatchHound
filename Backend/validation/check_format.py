import json
from logs.audit_trail import audit_trail_event

def check_json_format(audit_trail, file_obj):
    try:
        file_obj.seek(0)
        data = json.load(file_obj)

        if not isinstance(data, dict):
            return False
        if data.get("bomFormat") != "CycloneDX":
            return False
        if data.get("specVersion") != "1.6":
            return False
        if "components" not in data or not isinstance(data["components"], list):
            return False
        audit_trail_event(audit_trail, "SBOM_FORMAT", {
            "sbom_format": "cyclonedx"
        })
        return True
    except Exception:
        return False