import sqlite3
from core.Variables import db_path

def disable_key(license_key):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE Key_Validation SET Enabled = 0 WHERE LicenseKey = ?", (license_key,))
        conn.commit()
        conn.close()

        return "License key disabled"

    except Exception as e:
        print(f"Error: {str(e)}")
        return f"Failed to disable key: {str(e)}"
    
def enable_key(license_key):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE Key_Validation SET Enabled = 1 WHERE LicenseKey = ?", (license_key,))
        conn.commit()
        conn.close()

        return "License key enabled"

    except Exception as e:
        print(f"Error: {str(e)}")
        return f"Failed to enable key: {str(e)}"