import os
from file_system.cleanup.cleanup_local_scan_data import cleanup_max_entries_scan_data_local, cleanup_max_entries_age_scan_data_local
from external_storage.external_storage_cleanup import cleanup_external_storage_max_entries, cleanup_external_storage_max_entries_age

def cleanup_scan_data(audit_trail, scan_data_storage):

    if os.environ.get("cleanup_max_entries_scan_data_enabled", "False").lower() == "true":
        cleanup_max_entries_str = os.environ.get("cleanup_max_entries")
        cleanup_max_entries = int(cleanup_max_entries_str)

        if os.environ.get("external_storage_enabled", "False").lower() == "true":
            cleanup_external_storage_max_entries(audit_trail, scan_data_storage, cleanup_max_entries)
        else:
            cleanup_max_entries_scan_data_local(audit_trail, scan_data_storage, cleanup_max_entries)

    elif os.environ.get("cleanup_max_age_scan_data_enabled", "False").lower() == "true":
        max_entry_age_days_str = os.environ.get("max_entry_age_days")
        max_entry_age_days = int(max_entry_age_days_str)

        always_keep_entries_str = os.environ.get("always_keep_entries")
        always_keep_entries = int(always_keep_entries_str)

        if os.environ.get("external_storage_enabled", "False").lower() == "true":
            cleanup_external_storage_max_entries_age(audit_trail, scan_data_storage, max_entry_age_days, always_keep_entries)
        else:
            cleanup_max_entries_age_scan_data_local(audit_trail, scan_data_storage, max_entry_age_days, always_keep_entries)
            
    else:
        print("[!] Cleanup of scan_data not enabled. Pay attention to your storage or it could fill up!")