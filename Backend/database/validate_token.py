import sqlite3
from datetime import datetime
from utils.audit_trail import audit_trail_event
from core.variables import db_path

def validate_token(audit_trail, token_key):
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
        if audit_trail is not False:
            audit_trail_event(audit_trail, "TOKEN_VALIDATION", {
                "status": "valid",
                "expiration_date": expiration_date,
                "organization": organization
            })

        return organization, True

    except Exception as e:
        print(f"Error: {str(e)}")
        return f"Token validation: Internal error {str(e)}", False