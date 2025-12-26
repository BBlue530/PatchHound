import os
from external_storage.s3_handling.s3_send import send_files_to_s3

def send_files_to_external_storage(files_to_send_dir, bucket_dir):
    if os.environ.get("aws_s3_bucket_enabled", "False").lower() == "true":
        return send_files_to_s3(files_to_send_dir, bucket_dir)
    else:
        print("[+] External storage not enabled.") 
        return