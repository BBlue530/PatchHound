import sqlite3
import psycopg2
import os
from datetime import datetime, timedelta
import uuid
from core.variables import db_path

def create_key(organization, expiration_days):
    token_key = str(uuid.uuid4())
    expiration_date = (datetime.now() + timedelta(days=expiration_days)).strftime("%Y-%m-%d")
    enabled = 1

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
                INSERT INTO Key_Validation (TokenKey, Organization, ExpirationDate, Enabled)
                VALUES (%s, %s, %s, TRUE)
            """, (token_key, organization, expiration_date))

            conn.commit()
            cursor.close()
            conn.close()

            response = (
                f"Token Key Created For: {organization} "
                f"Key: {token_key} Expires: {expiration_date}"
            )
            return response

        except psycopg2.IntegrityError:
            return "Token creation error: Duplicate key"

        except Exception as e:
            print(f"Error: {str(e)}")
            return f"Token creation error: {str(e)}"
        
    else:
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO Key_Validation (TokenKey, Organization, ExpirationDate, Enabled)
                VALUES (?, ?, ?, ?)
            """, (token_key, organization, expiration_date, enabled))
            conn.commit()
            cursor.close()
            conn.close()

            response = f"Token Key Created For: {organization} Key: {token_key} Expires: {expiration_date}"
            return response

        except sqlite3.IntegrityError:
            return "Token creation error: Duplicate key"

        except Exception as e:
            print(f"Error: {str(e)}")
            return f"Token creation error: {str(e)}"