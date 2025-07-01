import json

def check_json_format(sbom_file):
    try:
        with open(sbom_file, 'r') as f:
            data = json.load(f)
        
        if not isinstance(data, dict):
            return False
        
        # Required for cyclonedx SBOM
        if data.get("bomFormat") != "CycloneDX":
            return False
        
        # Version check
        if data.get("specVersion") != "1.6":
            return False
        
        if not data.get("$schema", "").startswith("http://cyclonedx.org/schema/bom-1.6.schema.json"):
            return False
        
        # Check that components is a list
        if "components" not in data or not isinstance(data["components"], list):
            return False
        
        return True
    except Exception as e:
        return False