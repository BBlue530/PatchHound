import os
import json
import requests
from logs.audit_trail import audit_trail_event
from external_storage.external_storage_get import get_resources_external_storage_internal_use

def alert_event_system(audit_trail, message, alert, alert_config_path):
    alert_system_webhook = None

    if os.environ.get("external_storage_enabled", "False").lower() == "true":
        memory_file = get_resources_external_storage_internal_use(alert_config_path)
        alert_system_json = json.load(memory_file)
        print(alert_config_path)
        print(alert_system_json)
    else:
        if alert_config_path is None:
            audit_trail_event(audit_trail, "ALERT_SYSTEM", {
                    "status": "fail",
                    "alert_config": "not found",
                    "message": message
                })
            return
        else:
            with open(alert_config_path, "r") as f:
                alert_system_json = json.load(f)

    alert_system_webhook = alert_system_json.get("alert_system_webhook")

    if not alert_system_webhook:
        print("[!] Webhook URL missing")
        audit_trail_event(audit_trail, "ALERT_SYSTEM", {
            "status": "fail",
            "webhook": "not found",
            "message": message
        })
        return

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
        audit_trail_event(audit_trail, "ALERT_SYSTEM", {
            "status_code": response.status_code,
            "webhook": "discord",
            "message": message
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
        audit_trail_event(audit_trail, "ALERT_SYSTEM", {
            "status_code": response.status_code,
            "webhook": "slack",
            "message": message
        })
        
    else:
        audit_trail_event(audit_trail, "ALERT_SYSTEM", {
                "status": "fail",
                "webhook": "not found",
                "message": message
            })
        print("[!] Alert config not found!")