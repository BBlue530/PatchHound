import json

def check_json_format(file_obj):
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
        return True
    except Exception:
        return False