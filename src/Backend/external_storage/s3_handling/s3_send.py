import os
import boto3
from flask import request
from logs.export_logs import log_exporter

def send_files_to_s3(files_to_send_dir, bucket_dir):
    print("[+] AWS s3 enabled. Sending files...")

    bucket = os.environ.get("aws_s3_bucket")
    bucket_key_prefix = os.environ.get("aws_s3_bucket_key", "")

    s3 = boto3.client(
        "s3",
        aws_access_key_id=os.environ.get("aws_access_key_id"),
        aws_secret_access_key=os.environ.get("aws_secret_access_key"),
        region_name=os.environ.get("aws_default_region")
    )

    if os.path.isfile(files_to_send_dir):
        local_path = files_to_send_dir
        filename = os.path.basename(local_path)
        s3_key = os.path.join(bucket_key_prefix, bucket_dir, filename).replace("\\", "/")
        print(f"[~] Uploading file {local_path} -> s3://{bucket}/{s3_key}")
        s3.upload_file(local_path, bucket, s3_key)

    elif os.path.isdir(files_to_send_dir):
        for root, dirs, files in os.walk(files_to_send_dir):
            for file in files:
                local_path = os.path.join(root, file)
                relative_path = os.path.relpath(local_path, files_to_send_dir)
                s3_key = os.path.join(bucket_key_prefix, bucket_dir, relative_path).replace("\\", "/")
                print(f"[~] Uploading {local_path} -> s3://{bucket}/{s3_key}")
                s3.upload_file(local_path, bucket, s3_key)

    else:
        new_entry = {
            "message": f"Path does not exist: {files_to_send_dir}",
            "level": "error",
            "module": "send_files_to_s3",
            "client_ip": request.remote_addr,
        }
        log_exporter(new_entry)
        raise ValueError(f"Path does not exist: {files_to_send_dir}")
    
    print(f"[+] Sending '{files_to_send_dir}' to S3 bucket '{bucket}' completed.")
    return