import os
import sys
from config.helpers.expand_env_var import expand_env

def cleanup_config(app_config):
    cleanup_scan_data_enabled = app_config.get("backend", {}).get("storage", {}).get("cleanup", {}).get("cleanup_entries", {}).get("enabled", False)
    cleanup_old_scan_data_enabled = app_config.get("backend", {}).get("storage", {}).get("cleanup", {}).get("cleanup_old_entries", {}).get("enabled", False)

    if sum([cleanup_scan_data_enabled, cleanup_old_scan_data_enabled]) > 1:
        print("[!] More than 1 cleanup is enabled: [backend.storage.cleanup.]")
        sys.exit(1)

    if cleanup_scan_data_enabled:
        os.environ["cleanup_max_entries_scan_data_enabled"] = "True"

        cleanup_max_entries = expand_env(app_config.get("backend", {}).get("storage", {}).get("cleanup", {}).get("cleanup_entries", {}).get("max_entries", None))
        if cleanup_max_entries is not None:
            os.environ["cleanup_max_entries"] = str(cleanup_max_entries)

        print(f"[+] Cleanup of scan_data enabled. Will cleanup oldest entries when threshold of [{cleanup_max_entries}] is reached.")
    elif cleanup_old_scan_data_enabled:
        os.environ["cleanup_max_age_scan_data_enabled"] = "True"

        max_entry_age_month = expand_env(app_config.get("backend", {}).get("storage", {}).get("cleanup", {}).get("cleanup_old_entries", {}).get("max_entry_age", {}).get("month", 0))
        max_entry_age_week = expand_env(app_config.get("backend", {}).get("storage", {}).get("cleanup", {}).get("cleanup_old_entries", {}).get("max_entry_age", {}).get("week", 0))
        max_entry_age_day = expand_env(app_config.get("backend", {}).get("storage", {}).get("cleanup", {}).get("cleanup_old_entries", {}).get("max_entry_age", {}).get("day", 0))

        max_entry_age_days = max_entry_age_month * 4 * 7 + max_entry_age_week * 7 + max_entry_age_day

        os.environ["max_entry_age_days"] = str(max_entry_age_days)

        always_keep_entries = expand_env(app_config.get("backend", {}).get("storage", {}).get("cleanup", {}).get("cleanup_old_entries", {}).get("always_keep_entries", 0))

        os.environ["always_keep_entries"] = str(always_keep_entries)

        print(f"[+] Cleanup of old scan_data enabled. Will cleanup old entries with age [{max_entry_age_days}] days. Will always keep [{always_keep_entries}] entries.")
    else:
        print("[!] Cleanup of scan_data not enabled. Pay attention to your storage or it could fill up!")