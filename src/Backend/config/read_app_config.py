import yaml
from config.set_auth import aws_auth
from config.set_database_env import database_storage_config
from config.set_scan_data_env import scan_data_storage_config
from config.set_secret_data_env import secret_data_storage_config
from config.set_log_exporter import log_exporter_config
from config.set_cleanup_env import cleanup_config
from core.variables import app_config_path

def read_app_config():
    print("[+] Reading app config...")
    with open(app_config_path, "r") as f:
        app_config = yaml.safe_load(f)

    aws_auth(app_config)
    secret_data_storage_config(app_config)
    database_storage_config(app_config)
    scan_data_storage_config(app_config)
    log_exporter_config(app_config)
    cleanup_config(app_config)