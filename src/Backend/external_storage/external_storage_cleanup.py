import os
from external_storage.s3_handling.s3_cleanup import cleanup_max_entries_scan_data_s3, cleanup_max_entries_age_scan_data_s3

def cleanup_external_storage_max_entries(audit_trail, scan_data_storage, cleanup_max_entries):
    if os.environ.get("aws_s3_bucket_enabled", "False").lower() == "true":
        cleanup_max_entries_scan_data_s3(audit_trail, scan_data_storage, cleanup_max_entries)
    else:
        print("[+] External storage not enabled.")

def cleanup_external_storage_max_entries_age(audit_trail, scan_data_storage, max_entry_age_days, always_keep_entries):
    if os.environ.get("aws_s3_bucket_enabled", "False").lower() == "true":
        cleanup_max_entries_age_scan_data_s3(audit_trail, scan_data_storage, max_entry_age_days, always_keep_entries)
    else:
        print("[+] External storage not enabled.")