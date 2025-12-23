import sqlite3
import psycopg2
import os
from core.variables import db_path

def remove_key(token_key):
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
                "SELECT 1 FROM Key_Validation WHERE TokenKey = %s",
                (token_key,)
            )
            result = cursor.fetchone()

            if result is None:
                return "Token key does not exist"

            cursor.execute(
                "DELETE FROM Key_Validation WHERE TokenKey = %s",
                (token_key,)
            )

            conn.commit()
            cursor.close()
            conn.close()

            return "Token key removed"

        except Exception as e:
            print(f"Error: {str(e)}")
            return f"Failed to removed key: {str(e)}"
        
    else:
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute(
            "SELECT 1 FROM Key_Validation WHERE TokenKey = ?",
                (token_key,)
            )
            result = cursor.fetchone()

            if result is None:
                return "Token key does not exist"

            cursor.execute(
                "DELETE FROM Key_Validation WHERE TokenKey = ?",
                (token_key,)
            )
            
            conn.commit()
            cursor.close()
            conn.close()

            return "Token key removed"

        except Exception as e:
            print(f"Error: {str(e)}")
            return f"Failed to removed key: {str(e)}"