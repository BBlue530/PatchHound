import os
import sys
from config.helpers.expand_env_var import expand_env

def log_exporter_config(app_config):

    https_log_exporter_enabled = expand_env(app_config.get("backend", {}).get("storage", {}).get("export_log", {}).get("https", {}).get("enabled", False))
    opentelemetry_log_exporter_enabled = expand_env(app_config.get("backend", {}).get("storage", {}).get("export_log", {}).get("opentelemetry", {}).get("enabled", False))

    if sum([https_log_exporter_enabled, opentelemetry_log_exporter_enabled]) > 1:
        print("[!] More than 1 scan data storage is enabled: [backend.storage.export_log.]")
        sys.exit(1)
    
    if https_log_exporter_enabled:
        os.environ["https_log_exporter_enabled"] = "True"
        
        os.environ["https_log_export_url"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("export_log", {}).get("https", {}).get("export_url", None))
        os.environ["https_log_export_url_api_key"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("export_log", {}).get("https", {}).get("export_url_api_key", None))
        print("[+] Log https exporter set in environment")

    elif opentelemetry_log_exporter_enabled:
        os.environ["opentelemetry_log_exporter_enabled"] = "True"
        
        os.environ["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("export_log", {}).get("opentelemetry", {}).get("export_url", None))
        
        opentelemetry_log_export_url_api_key = expand_env(app_config.get("backend", {}).get("storage", {}).get("export_log", {}).get("opentelemetry", {}).get("export_url_api_key", None))
        if opentelemetry_log_export_url_api_key:
            os.environ["OTEL_EXPORTER_OTLP_HEADERS"] = f"Authorization=Bearer {opentelemetry_log_export_url_api_key}"
        
        os.environ["SERVICE_NAME"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("export_log", {}).get("opentelemetry", {}).get("service_name", None))
        os.environ["ENVIRONMENT"] = expand_env(app_config.get("backend", {}).get("storage", {}).get("export_log", {}).get("opentelemetry", {}).get("environment", None))

        print("[+] Log opentelemetry exporter set in environment")

    else:
        print("[+] Log exporter NOT set in environment.")