import yaml
from config.set_auth import aws_auth
from config.set_database_env import database_storage_config
from config.secret_data.get_secret_data import set_secrets_in_env
from core.variables import app_config_path

def read_app_config():
    print("[+] Reading app config...")
    with open(app_config_path, "r") as f:
        app_config = yaml.safe_load(f)

    aws_auth(app_config)
    set_secrets_in_env(app_config)
    database_storage_config(app_config)