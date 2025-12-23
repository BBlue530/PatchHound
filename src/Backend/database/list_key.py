import sqlite3
import psycopg2
import os
from core.variables import db_path

def list_all_keys():
    result_json = []
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
                "SELECT * FROM Key_Validation;"
            )

            result = cursor.fetchall()

            conn.commit()
            cursor.close()
            conn.close()

        except Exception as e:
            print(f"Error: {str(e)}")
            return f"Failed to removed key: {str(e)}"
        
    else:
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM Key_Validation;"
            )

            result = cursor.fetchall()
            
            conn.commit()
            cursor.close()
            conn.close()

        except Exception as e:
            print(f"Error: {str(e)}")
            return f"Failed to removed key: {str(e)}"
    
    for token_key, organization, expiration_date, enabled in result:
        result_json.append({
            "token_key": token_key,
            "organization": organization,
            "expiration_date": expiration_date,
            "enabled": enabled
        })
    
    return result_json