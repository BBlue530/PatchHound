import boto3
import os
    
def read_files_from_s3(dir_to_read):
    print("[+] AWS s3 enabled. Reading files...")

    bucket = os.environ.get("aws_s3_bucket")
    bucket_key_prefix = os.environ.get("aws_s3_bucket_key", "")

    s3 = boto3.client(
        "s3",
        aws_access_key_id=os.environ.get("aws_access_key_id"),
        aws_secret_access_key=os.environ.get("aws_secret_access_key"),
        region_name=os.environ.get("aws_default_region")
    )

    prefix = os.path.join(bucket_key_prefix, dir_to_read).replace("\\", "/")
    if prefix and not prefix.endswith("/"):
        prefix += "/"

    files = []
    paginator = s3.get_paginator("list_objects_v2")

    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            files.append(obj["Key"])

    return files