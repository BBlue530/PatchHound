import sqlite3
from core.variables import db_path

def disable_key(token_key):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE Key_Validation SET Enabled = 0 WHERE TokenKey = ?", (token_key,))
        conn.commit()
        conn.close()

        return "Token key disabled"

    except Exception as e:
        print(f"Error: {str(e)}")
        return f"Failed to disable key: {str(e)}"
    
def enable_key(token_key):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE Key_Validation SET Enabled = 1 WHERE TokenKey = ?", (token_key,))
        conn.commit()
        conn.close()

        return "Token key enabled"

    except Exception as e:
        print(f"Error: {str(e)}")
        return f"Failed to enable key: {str(e)}"