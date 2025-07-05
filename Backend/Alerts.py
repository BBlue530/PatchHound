import os
import json
import requests

def alert_system(message, alert, repo_name, repo_path):

    alert_path = os.path.join(repo_path, f"{repo_name}_alert.json")

    if not os.path.isfile(alert_path):
        print("[!] Alert config not found!")
        return

    if os.path.isfile(alert_path):
        with open(alert_path, "r") as f:
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