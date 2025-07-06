import os
import json
import requests

def alert_system(message, alert, alert_config_path):
    alert_system_name = None
    alert_system_webhook = None

    if os.path.isfile(alert_config_path):
        with open(alert_config_path, "r") as f:
            alert_system_json = json.load(f)

        alert_system = alert_system_json.get("alert_system")
        alert_system_webhook = alert_system_json.get("alert_system_webhook")

        if alert_system == "discord":
            payload = {
                "embeds": [{
                    "title": f"🚨 {alert}",
                    "description": message,
                    "color": 16711680
                }]
            }
            requests.post(
                alert_system_webhook,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"}
            )

        elif alert_system == "slack":
            payload = {
                "text": f":rotating_light: {alert}",
                "attachments": [
                    {
                        "color": "#FF0000",
                        "text": message
                    }
                ]
            }
            requests.post(
                alert_system_webhook,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"}
            )
    
    else:
        print("[!] Alert config not found!")