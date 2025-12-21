import json
import boto3
from botocore.exceptions import ClientError
import os

def append_to_s3(new_entry, repo_history_path):
    if os.environ.get("s3_bucket_enabled", "False").lower() == "true":
        print("[+] S3 enabled. Appending logs...")

        bucket = os.environ.get("s3_bucket")
        bucket_key_prefix = os.environ.get("s3_bucket_key", "")

        s3 = boto3.client(
            "s3",
            aws_access_key_id=os.environ.get("aws_access_key_id"),
            aws_secret_access_key=os.environ.get("aws_secret_access_key"),
            region_name=os.environ.get("aws_default_region")
        )

        s3_key = f"{bucket_key_prefix}/{repo_history_path}".lstrip("/")

        try:
            response = s3.get_object(Bucket=bucket, Key=s3_key)
            all_entries = json.loads(response["Body"].read())
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                all_entries = []
            else:
                raise
        except json.JSONDecodeError:
            all_entries = []

        all_entries.append(new_entry)
        s3.put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=json.dumps(all_entries, indent=4)
        )
        print(f"[+] History updated in s3: {repo_history_path}")
        return
    
    else:
        print("[+] S3 not enabled.")
        return