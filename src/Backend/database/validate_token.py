import sqlite3
import psycopg2
import os
from datetime import datetime
from logs.event_handler import event
from core.variables import db_path, log_type_info, log_type_debug, log_type_error, log_message_key, log_level_key, log_module_key, log_details_key

def validate_token(audit_trail, hashed_token_key):
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
            """, (hashed_token_key,))

            result = cursor.fetchone()
            cursor.close()
            conn.close()

            if result is None:
                event(audit_trail, {
                    log_message_key: "token missing",
                    log_level_key: log_type_info,
                    log_module_key: "token_validation",
                    log_details_key: {
                        "status": "failed",
                    }
                })
                return "Token validation: TokenKey Not Found", False

            expiration_date, enabled, organization = result

            if not enabled:
                event(audit_trail, {
                    log_message_key: "token disabled",
                    log_level_key: log_type_info,
                    log_module_key: "token_validation",
                    log_details_key: {
                        "status": "failed",
                        "expiration_date": expiration_date,
                        "organization": organization
                    }
                })
                return "Token validation: TokenKey Disabled", False

            if datetime.strptime(expiration_date, "%Y-%m-%d") < datetime.now():
                event(audit_trail, {
                    log_message_key: "token expired",
                    log_level_key: log_type_info,
                    log_module_key: "token_validation",
                    log_details_key: {
                        "status": "failed",
                        "expiration_date": expiration_date,
                        "organization": organization
                    }
                })
                return "Token validation: TokenKey Expired", False

            if audit_trail is not False:
                event(audit_trail, {
                    log_message_key: "token is valid",
                    log_level_key: log_type_info,
                    log_module_key: "token_validation",
                    log_details_key: {
                        "status": "valid",
                        "expiration_date": expiration_date,
                        "organization": organization
                    }
                })
            return organization, True

        except Exception as e:
            event(audit_trail, {
                log_message_key: "internal error",
                log_level_key: log_type_info,
                log_module_key: "token_validation",
                log_details_key: {
                    "status": "failed",
                    "error": str(e)
                }
            })
            return f"Token validation: Internal error {str(e)}", False
        
    else:
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ExpirationDate, Enabled, Organization 
                FROM Key_Validation 
                WHERE TokenKey = ?
            """, (hashed_token_key,))
            
            result = cursor.fetchone()
            cursor.close()
            conn.close()

            if result is None:
                event(audit_trail, {
                    log_message_key: "token missing",
                    log_level_key: log_type_info,
                    log_module_key: "token_validation",
                    log_details_key: {
                        "status": "failed",
                    }
                })
                return "Token validation: TokenKey Not Found", False

            expiration_date, enabled, organization = result

            if not enabled:
                event(audit_trail, {
                    log_message_key: "token disabled",
                    log_level_key: log_type_info,
                    log_module_key: "token_validation",
                    log_details_key: {
                        "status": "failed",
                        "expiration_date": expiration_date,
                        "organization": organization
                    }
                })
                return "Token validation: TokenKey Disabled", False

            if datetime.strptime(expiration_date, "%Y-%m-%d") < datetime.now():
                event(audit_trail, {
                    log_message_key: "token expired",
                    log_level_key: log_type_info,
                    log_module_key: "token_validation",
                    log_details_key: {
                        "status": "failed",
                        "expiration_date": expiration_date,
                        "organization": organization
                    }
                })
                return "Token validation: TokenKey Expired", False
            
            if audit_trail is not False:
                event(audit_trail, {
                    log_message_key: "token is valid",
                    log_level_key: log_type_info,
                    log_module_key: "token_validation",
                    log_details_key: {
                        "status": "valid",
                        "expiration_date": expiration_date,
                        "organization": organization
                    }
                })

            return organization, True

        except Exception as e:
            event(audit_trail, {
                log_message_key: "internal error",
                log_level_key: log_type_info,
                log_module_key: "token_validation",
                log_details_key: {
                    "status": "failed",
                    "error": str(e)
                }
            })
            return f"Token validation: Internal error {str(e)}", False