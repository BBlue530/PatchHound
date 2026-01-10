import os
import boto3
from datetime import datetime, timezone, timedelta
from logs.audit_trail import audit_trail_event

def cleanup_max_entries_scan_data_s3(audit_trail, scan_data_storage, cleanup_max_entries):
    print("[~] Cleanup of scan_data s3 bucket started...")

    all_objects = []
    objects_with_timestamp = []

    bucket = os.environ.get("aws_s3_bucket")
    bucket_key_prefix = os.environ.get("aws_s3_bucket_key", "").strip("/")

    scan_data_storage_strip = scan_data_storage.strip("/")

    prefix = f"{bucket_key_prefix}/{scan_data_storage_strip}/" if bucket_key_prefix else f"{scan_data_storage_strip}/"

    s3 = boto3.client(
        "s3",
        aws_access_key_id=os.environ.get("aws_access_key_id"),
        aws_secret_access_key=os.environ.get("aws_secret_access_key"),
        region_name=os.environ.get("aws_default_region")
    )

    paginator = s3.get_paginator("list_objects_v2")

    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        all_objects.extend(page.get("Contents", []))

    for obj in all_objects:
        key = obj["Key"]
        if not key:
            continue

        relative = key[len(prefix):]
        if "/" not in relative:
            continue
        timestamp = relative.split("/", 1)[0]

        objects_with_timestamp.append({
            "timestamp": timestamp,
            "key": key,
            "object": obj,
        })

    timestamps = sorted({ts["timestamp"] for ts in objects_with_timestamp}, reverse=True)

    to_delete_timestamps = set(timestamps[cleanup_max_entries:])

    to_delete = [
        timestamp for timestamp in objects_with_timestamp
        if timestamp["timestamp"] in to_delete_timestamps
    ]

    for timestamp_delete in to_delete:
        print(f"[~] Deleting old scan_data: {timestamp_delete['key']}")
        s3.delete_object(Bucket=bucket, Key=timestamp_delete["key"])

    audit_trail_event(audit_trail, "CLEANUP_SCAN_DATA", {
        "to_delete": sorted(to_delete_timestamps),
        "location": "s3",
        "prefix": prefix,
        "cleanup_max_entries": cleanup_max_entries,
    })
    print("[+] Cleanup completed.")

def cleanup_max_entries_age_scan_data_s3(audit_trail, scan_data_storage, max_entry_age_days, always_keep_entries):
    print("[~] Cleanup of scan_data s3 bucket started...")

    objects_with_timestamp = []
    all_objects = []
    to_delete_timestamps = []

    bucket = os.environ.get("aws_s3_bucket")
    bucket_key_prefix = os.environ.get("aws_s3_bucket_key", "").strip("/")

    scan_data_storage_strip = scan_data_storage.strip("/")

    prefix = f"{bucket_key_prefix}/{scan_data_storage_strip}/" if bucket_key_prefix else f"{scan_data_storage_strip}/"

    timestamp_format = "%Y%m%d_%H%M%S"
    max_age_delta = timedelta(days=max_entry_age_days)
    now = datetime.now(timezone.utc)
    cutoff = now - max_age_delta

    s3 = boto3.client(
        "s3",
        aws_access_key_id=os.environ.get("aws_access_key_id"),
        aws_secret_access_key=os.environ.get("aws_secret_access_key"),
        region_name=os.environ.get("aws_default_region")
    )

    paginator = s3.get_paginator("list_objects_v2")

    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        all_objects.extend(page.get("Contents", []))

    for obj in all_objects:
        key = obj["Key"]
        if not key:
            continue

        relative = key[len(prefix):]
        if "/" not in relative:
            continue
        timestamp = relative.split("/", 1)[0]

        objects_with_timestamp.append({
            "timestamp": timestamp,
            "key": key,
            "object": obj,
        })

    timestamps = sorted({ts["timestamp"] for ts in objects_with_timestamp}, reverse=True)

    if len(timestamps) < always_keep_entries:
        print("[+] No cleanup needed")
        return

    for ts in timestamps:
        try:
            ts_dt = datetime.strptime(ts, timestamp_format).replace(tzinfo=timezone.utc)
            if ts_dt < cutoff:
                to_delete_timestamps.append(ts)
        except ValueError:
            print(f"[!] Skipping invalid timestamp folder: {ts}")

    to_delete = [
        timestamp for timestamp in objects_with_timestamp
        if timestamp["timestamp"] in to_delete_timestamps
    ]

    for timestamp_delete in to_delete:
        print(f"[~] Deleting old scan_data: {timestamp_delete['key']}")
        s3.delete_object(Bucket=bucket, Key=timestamp_delete["key"])

    audit_trail_event(audit_trail, "CLEANUP_SCAN_DATA", {
        "to_delete": sorted(to_delete_timestamps),
        "location": "s3",
        "prefix": prefix,
        "always_keep_entries": always_keep_entries,
        "max_entry_age_days": max_entry_age_days,
    })
    print("[+] Cleanup completed.")