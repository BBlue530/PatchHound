import sqlite3
import psycopg2
import os
from core.variables import db_path, DB_DIR_PATH

def create_database():
    if os.environ.get("external_database_enabled", "False").lower() == "true":
        conn = psycopg2.connect(
            dbname=os.environ.get("external_database_name"),
            user=os.environ.get("external_database_username"),
            password=os.environ.get("external_database_password"),
            host=os.environ.get("external_database_host"),
            port=5432
        )
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS Key_Validation (
                TokenKey TEXT PRIMARY KEY,
                Organization TEXT NOT NULL,
                ExpirationDate TEXT NOT NULL,
                Enabled BOOLEAN NOT NULL
            )
        """)

        conn.commit()
        cursor.close()
        conn.close()
        print("[+] External PostgreSQL database and table created successfully.")

    else:
        os.makedirs(DB_DIR_PATH, exist_ok=True)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS Key_Validation (
                TokenKey TEXT PRIMARY KEY,
                Organization TEXT NOT NULL,
                ExpirationDate TEXT NOT NULL,
                Enabled INTEGER NOT NULL CHECK (Enabled IN (0,1))
            )
        """)

        conn.commit()
        cursor.close()
        conn.close()
        print("[+] Database and table created successfully.")