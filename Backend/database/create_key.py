import sqlite3
from datetime import datetime, timedelta
import uuid
from core.variables import db_path

def create_key(organization, expiration_days):
    token_key = str(uuid.uuid4())
    expiration_date = (datetime.now() + timedelta(days=expiration_days)).strftime("%Y-%m-%d")
    enabled = 1

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Key_Validation (TokenKey, Organization, ExpirationDate, Enabled)
            VALUES (?, ?, ?, ?)
        """, (token_key, organization, expiration_date, enabled))
        conn.commit()
        conn.close()

        response = f"Token Key Created For: {organization} Key: {token_key} Expires: {expiration_date}"
        return response

    except sqlite3.IntegrityError:
        return "Token creation error: Duplicate key"

    except Exception as e:
        print(f"Error: {str(e)}")
        return f"Token creation error: {str(e)}"