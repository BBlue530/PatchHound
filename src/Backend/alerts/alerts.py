import os
import json
import requests
from logs.event_handler import event
from utils.helpers import load_file_data
from external_storage.external_storage_get import get_resources_external_storage_internal_use
from core.variables import log_type_info, log_type_debug, log_type_error, log_message_key, log_level_key, log_module_key, log_details_key

def alert_event_system(audit_trail, message, alert, alert_config_path):
    alert_system_webhook = None

    if os.environ.get("external_storage_enabled", "False").lower() == "true":
        memory_file = get_resources_external_storage_internal_use(alert_config_path)
        alert_system_json = json.load(memory_file)
        alert_system_webhook = alert_system_json.get("alert_system_webhook")
    else:
        if not os.path.isfile(alert_config_path):
            alert_system_webhook = os.environ.get("global_alert_webhook")
            if not alert_system_webhook:
                event(audit_trail, {
                    log_message_key: "webhook missing",
                    log_level_key: log_type_error,
                    log_module_key: "alerts",
                    log_details_key: {
                        "status": "fail",
                        "alert_config": "not found",
                        "alert_message": message
                    }
                })
                return
        else:
            alert_system_json = load_file_data(alert_config_path)
            alert_system_webhook = alert_system_json.get("alert_system_webhook")

    if "discord" in alert_system_webhook:
        payload = {
            "embeds": [{
                "title": f"🚨 {alert}",
                "description": message,
                "color": 16711680
            }]
        }
        response = requests.post(
            alert_system_webhook,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"}
        )
        event(audit_trail, {
            log_message_key: "alert sent using discord webhook",
            log_level_key: log_type_info,
            log_module_key: "discord_alert",
            log_details_key: {
                "status_code": response.status_code,
                "webhook": "discord",
                "alert_message": message
            }
        })

        if response.status_code not in [200, 204]:
            event(audit_trail, {
                log_message_key: "failed to send alert over discord webhook",
                log_level_key: log_type_error,
                log_module_key: "discord_alert",
                log_details_key: {
                    "status_code": response.status_code,
                    "webhook": "discord",
                    "alert_message": message
                }
            })

    elif "slack" in alert_system_webhook:
        payload = {
            "text": f":rotating_light: {alert}",
            "attachments": [
                {
                    "color": "#FF0000",
                    "text": message
                    }
            ]
        }
        response = requests.post(
            alert_system_webhook,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"}
        )
        event(audit_trail, {
            log_message_key: "alert sent using slack webhook",
            log_level_key: log_type_info,
            log_module_key: "slack_alert",
            log_details_key: {
                "status_code": response.status_code,
                "webhook": "slack",
                "alert_message": message
            }
        })

        if response.status_code not in [200, 204]:
            event(audit_trail, {
                log_message_key: "failed to send alert over slack webhook",
                log_level_key: log_type_error,
                log_module_key: "slack_alerts",
                log_details_key: {
                    "status_code": response.status_code,
                    "webhook": "slack",
                    "alert_message": message
                }
            })
        
    else:
        event(audit_trail, {
            log_message_key: "webhook not allowed",
            log_level_key: log_type_error,
            log_module_key: "alert",
            log_details_key: {
                "status": "fail",
                "webhook": "unallowed webhook configured",
                "alert_message": message
            }
        })