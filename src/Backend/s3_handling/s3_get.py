import os
import io
import zipfile
import boto3
import tempfile
from flask import abort, send_file
from botocore.exceptions import ClientError

def get_resources_s3(base_dir, file_names):
    if os.environ.get("s3_bucket_enabled", "False").lower() == "true":
        print("[+] S3 enabled. Getting resources...")

        bucket = os.environ.get("s3_bucket")
        bucket_key_prefix = os.environ.get("s3_bucket_key", "")

        s3 = boto3.client(
            "s3",
            aws_access_key_id=os.environ.get("aws_access_key_id"),
            aws_secret_access_key=os.environ.get("aws_secret_access_key"),
            region_name=os.environ.get("aws_default_region")
        )

        prefix = os.path.join(bucket_key_prefix, base_dir).replace("\\", "/")
        if not prefix.endswith("/"):
            prefix += "/"

        if file_names is None:
            paginator = s3.get_paginator("list_objects_v2")
            keys = []
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    if not obj["Key"].endswith("/"):
                        keys.append(obj["Key"])
        else:
            if isinstance(file_names, str):
                file_names = [file_names]

            keys = [
                os.path.join(prefix, fname).replace("\\", "/")
                for fname in file_names
            ]

        if not keys:
            abort(404, description="No files found to return")

        if len(keys) == 1:
            key = keys[0]
            memory_file = io.BytesIO()
            try:
                s3.download_fileobj(bucket, key, memory_file)
            except s3.exceptions.NoSuchKey:
                abort(404, description=f"Requested file not found: {key}")

            memory_file.seek(0)
            return send_file(memory_file, download_name=os.path.basename(key), as_attachment=True)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for key in keys:
                try:
                    file_buffer = io.BytesIO()
                    s3.download_fileobj(bucket, key, file_buffer)
                    file_buffer.seek(0)
                    zf.writestr(os.path.basename(key), file_buffer.read())
                except s3.exceptions.NoSuchKey:
                    print(f"requested file not found: {key}")

        zip_buffer.seek(0)
        return send_file(zip_buffer, download_name="resources.zip", as_attachment=True)
    
    else:
        print("[+] S3 not enabled.") 
        return
    
def get_resource_s3_internal_use(resource_to_get):
    if os.environ.get("s3_bucket_enabled", "False").lower() == "true":

        bucket = os.environ.get("s3_bucket")
        bucket_key_prefix = os.environ.get("s3_bucket_key", "")

        s3 = boto3.client(
            "s3",
            aws_access_key_id=os.environ.get("aws_access_key_id"),
            aws_secret_access_key=os.environ.get("aws_secret_access_key"),
            region_name=os.environ.get("aws_default_region")
        )

        key = os.path.join(bucket_key_prefix, resource_to_get).replace("\\", "/")

        memory_file = io.BytesIO()
        try:
            s3.download_fileobj(bucket, key, memory_file)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                raise FileNotFoundError(f"Requested file not found: {key}") from e
            else:
                raise RuntimeError(f"S3 download error: {e}") from e

        memory_file.seek(0)

        return memory_file

    else:
        print("[+] S3 not enabled.") 
        return
    
def get_all_resources_s3_internal_use_tmp(resource_to_get):
    if os.environ.get("s3_bucket_enabled", "False").lower() == "true":

        bucket = os.environ.get("s3_bucket")
        bucket_key_prefix = os.environ.get("s3_bucket_key", "")
        prefix = f"{bucket_key_prefix}/{resource_to_get}".lstrip("/")

        s3 = boto3.client(
            "s3",
            aws_access_key_id=os.environ.get("aws_access_key_id"),
            aws_secret_access_key=os.environ.get("aws_secret_access_key"),
            region_name=os.environ.get("aws_default_region")
        )

        temp_root = tempfile.mkdtemp(prefix="s3_resources_")

        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]

                if key.endswith("/"):
                    continue

                relative_path = os.path.relpath(key, prefix)
                local_path = os.path.join(temp_root, relative_path)

                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                s3.download_file(bucket, key, local_path)

        return temp_root

    else:
        print("[+] S3 not enabled.") 
        return