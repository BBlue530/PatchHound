import sqlite3
from datetime import datetime
from core.Variables import db_path

def validate_token(token_key):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT ExpirationDate, Enabled, Organization 
            FROM Key_Validation 
            WHERE TokenKey = ?
        """, (token_key,))
        
        result = cursor.fetchone()
        conn.close()

        if result is None:
            return "Token validation: TokenKey Not Found", False

        expiration_date, enabled, organization = result

        if not enabled:
            return "Token validation: TokenKey Disabled", False

        if datetime.strptime(expiration_date, "%Y-%m-%d") < datetime.now():
            return "Token validation: TokenKey Expired", False

        return organization, True

    except Exception as e:
        print(f"Error: {str(e)}")
        return f"Token validation: Internal error {str(e)}", False