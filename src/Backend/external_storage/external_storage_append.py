import os
from external_storage.s3_handling.s3_append import append_to_s3

def append_to_external_storage(new_entry, append_file_path):
    if os.environ.get("aws_s3_bucket_enabled", "False").lower() == "true":
        return append_to_s3(new_entry, append_file_path)
    else:
        print("[+] External storage not enabled.")
        return