import sqlite3
import psycopg2
import os
from datetime import datetime
from logs.audit_trail import audit_trail_event
from core.variables import db_path

def validate_token(audit_trail, token_key):
    if os.environ.get("external_database_enabled", "False").lower() == "true":
        try:
            conn = psycopg2.connect(
                dbname=os.environ.get("external_database_name"),
                user=os.environ.get("external_database_username"),
                password=os.environ.get("external_database_password"),
                host=os.environ.get("external_database_host"),
                port=5432
            )
            cursor = conn.cursor()

            cursor.execute("""
                SELECT ExpirationDate, Enabled, Organization
                FROM Key_Validation
                WHERE TokenKey = %s
            """, (token_key,))

            result = cursor.fetchone()
            cursor.close()
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
        
    else:
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ExpirationDate, Enabled, Organization 
                FROM Key_Validation 
                WHERE TokenKey = ?
            """, (token_key,))
            
            result = cursor.fetchone()
            cursor.close()
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