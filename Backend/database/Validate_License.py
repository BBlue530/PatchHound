import sqlite3
from datetime import datetime
from core.Variables import db_path

def validate_license(license_key):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT ExpirationDate, Enabled FROM Key_Validation WHERE LicenseKey = ?", (license_key,))
        result = cursor.fetchone()
        conn.close()

        if result is None:
            return "License validation: LicenseKey Not Found", False

        expiration_date, enabled = result

        if not enabled:
            return "License validation: LicenseKey Disabled", False

        if datetime.strptime(expiration_date, "%Y-%m-%d") < datetime.now():
            return "License validation: LicenseKey Expired", False

        return "License validation: LicenseKey Valid", True

    except Exception as e:
        print(f"Error: {str(e)}")
        return f"License validation: Internal error {str(e)}", False