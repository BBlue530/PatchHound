import os
from config.helpers.expand_env_var import expand_env

def rescan_alert_config(app_config):
    os.environ["rescan_alert_kev_vulns"] = expand_env(app_config.get("backend", {}).get("alert", {}).get("rescan_alert", {}).get("kev_vulns", False))
    os.environ["rescan_alert_vulns"] = expand_env(app_config.get("backend", {}).get("alert", {}).get("rescan_alert", {}).get("vulns", False))
    os.environ["global_alert_webhook"] = expand_env(app_config.get("backend", {}).get("alert", {}).get("webhook", False))
    print("[+] Alert config set")