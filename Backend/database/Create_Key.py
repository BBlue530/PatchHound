import sqlite3
from datetime import datetime, timedelta
import uuid
from core.Variables import db_path

def create_key(organization, expiration_days):
    license_key = str(uuid.uuid4())
    expiration_date = (datetime.now() + timedelta(days=expiration_days)).strftime("%Y-%m-%d")
    enabled = 1

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Key_Validation (LicenseKey, Organization, ExpirationDate, Enabled)
            VALUES (?, ?, ?, ?)
        """, (license_key, organization, expiration_date, enabled))
        conn.commit()
        conn.close()

        response = f"License Key Created For: {organization} Key: {license_key} Expires: {expiration_date}"
        return response

    except sqlite3.IntegrityError:
        return "License creation error: Duplicate key"

    except Exception as e:
        print(f"Error: {str(e)}")
        return f"License creation error: {str(e)}"