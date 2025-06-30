import requests
import json
from Variables import lambda_api_gateway_url

def validate_license(license_key):
    headers = {"Content-Type": "application/json"}

    data = {
        "LicenseKey": license_key
    }

    try:
        response = requests.post(lambda_api_gateway_url, headers=headers, data=json.dumps(data))

        if response.status_code == 200:
            message = response.json().get('message', 'Unknown success message')
            print("License = valid")
            return f"License validation: {message}", True
        else:
            message = response.json().get('message', 'Unknown error')
            print(f"License validation failed: {message}")
            return f"License validation: {message}", False

    except Exception as e:
        print(f"Error: {e}")
        return f"License validation error: {str(e)}", False