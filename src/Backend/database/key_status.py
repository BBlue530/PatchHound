import sqlite3
import psycopg2
import os
from core.variables import db_path

def disable_key(token_key):
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

            cursor.execute(
                "UPDATE Key_Validation SET Enabled = FALSE WHERE TokenKey = %s",
                (token_key,)
            )

            conn.commit()
            cursor.close()
            conn.close()

            return "Token key disabled"

        except Exception as e:
            print(f"Error: {str(e)}")
            return f"Failed to disable key: {str(e)}"
        
    else:
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("UPDATE Key_Validation SET Enabled = 0 WHERE TokenKey = ?", (token_key,))
            conn.commit()
            cursor.close()
            conn.close()

            return "Token key disabled"

        except Exception as e:
            print(f"Error: {str(e)}")
            return f"Failed to disable key: {str(e)}"
    
def enable_key(token_key):
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

            cursor.execute(
                "UPDATE Key_Validation SET Enabled = TRUE WHERE TokenKey = %s",
                (token_key,)
            )

            conn.commit()
            cursor.close()
            conn.close()

            return "Token key enabled"

        except Exception as e:
            print(f"Error: {str(e)}")
            return f"Failed to enable key: {str(e)}"
        
    else:
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("UPDATE Key_Validation SET Enabled = 1 WHERE TokenKey = ?", (token_key,))
            conn.commit()
            cursor.close()
            conn.close()

            return "Token key enabled"

        except Exception as e:
            print(f"Error: {str(e)}")
            return f"Failed to enable key: {str(e)}"