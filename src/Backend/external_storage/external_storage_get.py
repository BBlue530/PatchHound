import os
from external_storage.s3_handling.s3_get import get_resources_s3, get_resource_s3_internal_use, get_all_resources_s3_internal_use_tmp

def get_resources_external_storage(base_dir, file_names):
    if os.environ.get("aws_s3_bucket_enabled", "False").lower() == "true":
        return get_resources_s3(base_dir, file_names)
    else:
        print("[+] External storage not enabled.") 
        return
    
def get_resources_external_storage_internal_use(resource_to_get):
    if os.environ.get("aws_s3_bucket_enabled", "False").lower() == "true":
        return get_resource_s3_internal_use(resource_to_get)
    else:
        print("[+] External storage not enabled.") 
        return
    
def get_resources_external_storage_internal_use_tmp(resource_to_get):
    if os.environ.get("aws_s3_bucket_enabled", "False").lower() == "true":
        return get_all_resources_s3_internal_use_tmp(resource_to_get)
    else:
        print("[+] External storage not enabled.") 
        return