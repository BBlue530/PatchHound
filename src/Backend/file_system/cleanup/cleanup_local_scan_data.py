import os
import shutil
from datetime import datetime, timezone, timedelta
from file_system.cleanup.cleanup_helpers import remove_stubborn_backup
from logs.event_handler import event
from core.variables import log_type_info, log_type_debug, log_type_error, log_message_key, log_level_key, log_module_key, log_details_key

def cleanup_max_entries_scan_data_local(audit_trail, scan_data_storage, cleanup_max_entries):
    print("[~] Cleanup of local scan_data started...")

    all_folders = [f for f in os.listdir(scan_data_storage)
                if os.path.isdir(os.path.join(scan_data_storage, f))]
        
    timestamps = sorted(all_folders, reverse=True)
    to_delete = timestamps[cleanup_max_entries:]
        
    for folder in to_delete:
        folder_path = os.path.join(scan_data_storage, folder)
        print(f"[~] Deleting old backup folder: {folder_path}")
        shutil.rmtree(folder_path, onerror=remove_stubborn_backup)
    
    if to_delete:
        event(audit_trail, {
            log_message_key: "cleanup of local 'max_entries' completed",
            log_level_key: log_type_info,
            log_module_key: "cleanup_max_entries_scan_data_local",
            log_details_key: {
                "to_delete": to_delete,
                "location": "local",
                "cleanup_max_entries": cleanup_max_entries,
            }
        })

    else:
        event(audit_trail, {
            log_message_key: "cleanup of local 'max_entries' not needed",
            log_level_key: log_type_info,
            log_module_key: "cleanup_max_entries_scan_data_local",
            log_details_key: {
                "to_delete": "no_cleanup_needed",
                "location": "local",
                "cleanup_max_entries": cleanup_max_entries,
            }
        })

def cleanup_max_entries_age_scan_data_local(audit_trail, scan_data_storage, max_entry_age_days, always_keep_entries):
    print("[~] Cleanup of local scan_data started...")

    to_delete_timestamps = []

    timestamp_format = "%Y%m%d_%H%M%S"
    max_age_delta = timedelta(days=max_entry_age_days)
    now = datetime.now(timezone.utc)
    cutoff = now - max_age_delta

    all_folders = [f for f in os.listdir(scan_data_storage)
                if os.path.isdir(os.path.join(scan_data_storage, f))]
        
    timestamps = sorted(all_folders, reverse=True)

    timestamps_consider = timestamps[always_keep_entries:]

    if len(timestamps) < always_keep_entries:
        event(audit_trail, {
            log_message_key: "cleanup of local 'max_entries_age' not needed. Currently under threshold of entries to keep",
            log_level_key: log_type_info,
            log_module_key: "cleanup_max_entries_age_scan_data_local",
            log_details_key: {
                "always_keep_entries": always_keep_entries
            }
        })
        return
    
    for ts in timestamps_consider:
        try:
            ts_dt = datetime.strptime(ts, timestamp_format).replace(tzinfo=timezone.utc)
            if ts_dt < cutoff:
                to_delete_timestamps.append(ts)
        except ValueError:
            print(f"[!] Skipping invalid timestamp folder: {ts}")
        
    for folder in to_delete_timestamps:
        folder_path = os.path.join(scan_data_storage, folder)
        print(f"[~] Deleting old backup folder: {folder_path}")
        shutil.rmtree(folder_path, onerror=remove_stubborn_backup)
    
    if to_delete_timestamps:
        event(audit_trail, {
            log_message_key: "cleanup of local 'max_entries_age' completed",
            log_level_key: log_type_info,
            log_module_key: "cleanup_max_entries_age_scan_data_local",
            log_details_key: {
                "to_delete": to_delete_timestamps,
                "location": "local",
            }
        })

    else:
        event(audit_trail, {
            log_message_key: "cleanup of local 'max_entries_age' not needed",
            log_level_key: log_type_info,
            log_module_key: "cleanup_max_entries_age_scan_data_local",
            log_details_key: {
                "to_delete": "no_cleanup_needed",
                "location": "local",
            }
        })