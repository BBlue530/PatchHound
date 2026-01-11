import os
import shutil
from datetime import datetime, timezone, timedelta
from logs.audit_trail import audit_trail_event
from file_system.cleanup.cleanup_helpers import remove_stubborn_backup
from logs.export_logs import log_exporter

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
        new_entry = {
            "message": f"Cleanup of local 'max_entries' completed. Scan data deleted: [{to_delete}]. Cleanup max entries [{cleanup_max_entries}]",
            "level": "info",
            "module": "cleanup_max_entries_scan_data_local",
        }
        log_exporter(new_entry)
        audit_trail_event(audit_trail, "CLEANUP_SCAN_DATA", {
            "to_delete": to_delete,
            "location": "local",
            "cleanup_max_entries": cleanup_max_entries,
        })
    else:
        new_entry = {
            "message": f"Cleanup of local 'max_entries' not needed. Cleanup max entries [{cleanup_max_entries}]",
            "level": "info",
            "module": "cleanup_max_entries_scan_data_local",
        }
        log_exporter(new_entry)
        audit_trail_event(audit_trail, "CLEANUP_SCAN_DATA", {
            "to_delete": "no_cleanup_needed",
            "location": "local",
            "cleanup_max_entries": cleanup_max_entries,
        })
        
    print("[+] Local cleanup completed.")

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
        new_entry = {
            "message": f"Cleanup of local 'max_entries_age' not needed. Currently under threshold of entries to keep: [{always_keep_entries}]. Scan data is currently under threshold.",
            "level": "info",
            "module": "cleanup_max_entries_age_scan_data_local",
        }
        log_exporter(new_entry)
        print("[+] No cleanup needed")
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
        new_entry = {
            "message": f"Cleanup of local 'max_entries_age' completed. Scan data deleted: [{to_delete_timestamps}]. Currently under threshold of entries to keep: [{always_keep_entries}]",
            "level": "info",
            "module": "cleanup_max_entries_age_scan_data_local",
        }
        log_exporter(new_entry)
        audit_trail_event(audit_trail, "CLEANUP_SCAN_DATA", {
            "to_delete": to_delete_timestamps,
            "location": "local",
        })
    else:
        new_entry = {
            "message": f"Cleanup of local 'max_entries_age' not needed. Currently under threshold of entries to keep: [{always_keep_entries}]",
            "level": "info",
            "module": "cleanup_max_entries_age_scan_data_local",
        }
        log_exporter(new_entry)
        audit_trail_event(audit_trail, "CLEANUP_SCAN_DATA", {
            "to_delete": "no_cleanup_needed",
            "location": "local",
        })
        
    print("[+] Local cleanup completed.")