import os
from external_storage.s3_handling.s3_read import read_files_from_s3

def read_files_from_external_storage(dir_to_read):
    if os.environ.get("aws_s3_bucket_enabled", "False").lower() == "true":
        return read_files_from_s3(dir_to_read)
    else:
        print("[+] External storage not enabled.") 
        return