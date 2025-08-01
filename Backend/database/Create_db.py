import sqlite3
from core.Variables import db_path

def create_database():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Key_Validation (
            LicenseKey TEXT PRIMARY KEY,
            Organization TEXT NOT NULL,
            ExpirationDate TEXT NOT NULL,
            Enabled INTEGER NOT NULL CHECK (Enabled IN (0,1))
        )
    """)

    conn.commit()
    conn.close()
    print("Database and table created successfully.")