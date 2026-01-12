import os
import sys
from datetime import datetime
from config.helpers.expand_env_var import expand_env

def scheduled_rescan_config(app_config):

    scheduled_rescan_enabled = expand_env(app_config.get("backend", {}).get("scheduled_rescan", {}).get("enabled", False))

    if sum([scheduled_rescan_enabled]) > 1:
        print("[!] More than 1 scheduled rescan is enabled: [backend.scheduled_rescan.]")
        sys.exit(1)
    
    if scheduled_rescan_enabled:
        scheduled_rescan_month = expand_env(app_config.get("backend", {}).get("scheduled_rescan", {}).get("rescan_interval", {}).get("month", 0))
        scheduled_rescan_week = expand_env(app_config.get("backend", {}).get("scheduled_rescan", {}).get("rescan_interval", {}).get("week", 0))
        scheduled_rescan_day = expand_env(app_config.get("backend", {}).get("scheduled_rescan", {}).get("rescan_interval", {}).get("day", 0))

        if scheduled_rescan_month >= 0:
            scheduled_rescan_month_to_days = scheduled_rescan_month * 4 * 7
        
        if scheduled_rescan_week >= 0:
            scheduled_rescan_week_to_days = scheduled_rescan_week * 7
                
        scheduled_rescan_in_days = scheduled_rescan_day + scheduled_rescan_week_to_days + scheduled_rescan_month_to_days

        if scheduled_rescan_in_days <= 0:
            print("[!] Scheduled rescan not set or all values are 0. [backend.scheduled_rescan.]")
            sys.exit(1)
        
        os.environ["scheduled_rescan_in_days"] = str(scheduled_rescan_in_days)