import shutil
import os
from core.variables import all_resources_folder

def cleanup_scan_data():
    if os.environ.get("s3_bucket_enabled", "False").lower() == "true":
        if os.path.exists(all_resources_folder):
            shutil.rmtree(all_resources_folder)