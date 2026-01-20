import shutil
import os
from core.variables import all_resources_folder

def cleanup():
    if os.environ.get("external_storage_enabled", "False").lower() == "true":
        if os.path.exists(all_resources_folder):
            shutil.rmtree(all_resources_folder)