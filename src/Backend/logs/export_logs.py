import os
import requests
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry._logs import set_logger_provider
import logging
from datetime import datetime, timezone
from external_storage.external_storage_append import append_to_external_storage
from logs.audit_trail import append_audit_log
from core.variables import service_log_path

logger = logging.getLogger("application")

def log_exporter(new_entry):
    new_entry["service_timestamp"] = datetime.now(timezone.utc).isoformat()

    if os.environ.get("external_storage_enabled", "False").lower() == "true":
        append_to_external_storage(new_entry, service_log_path)
    else:
        os.makedirs(os.path.dirname(service_log_path), exist_ok=True)
        append_audit_log(service_log_path, new_entry)
    
    if os.environ.get("https_log_exporter_enabled", "False").lower() == "true":
        https_log_export_url = os.environ.get("https_log_export_url")
        https_log_export_url_api_key = os.environ.get("https_log_export_url_api_key")
        
        headers = {}
        if https_log_export_url_api_key:
            headers["Authorization"] = f"Bearer {https_log_export_url_api_key}"

        try:
            response = requests.post(https_log_export_url, json=new_entry, headers=headers, timeout=60)
            response.raise_for_status()

            print(f"[+] Exported logs successfully. url: [{https_log_export_url}]")
        except requests.exceptions.RequestException as e:
            print(f"[!] Failed exported logs. url: [{https_log_export_url}] Error: {e}")

    elif os.environ.get("opentelemetry_log_exporter_enabled", "False").lower() == "true":
        logger.info(
            new_entry.get("message", str(new_entry)),
            extra={
                "attributes": {
                    "message": new_entry.get("message", None),
                    "level": new_entry.get("level", "info"),
                    "module": new_entry.get("module"),
                    "client_ip": new_entry.get("client_ip", None),
                    "service_timestamp": new_entry.get("service_timestamp", None),
                }
            }
        )

def setup_opentelemetry_logging():
    resource = Resource.create({
        "service.name": os.environ.get("SERVICE_NAME", "unknown-service"),
        "service.environment": os.environ.get("ENVIRONMENT", "dev"),
    })

    provider = LoggerProvider(resource=resource)
    set_logger_provider(provider)

    exporter = OTLPLogExporter(
        endpoint=os.environ.get("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"),
        headers=os.environ.get("OTEL_EXPORTER_OTLP_HEADERS", "")
    )

    provider.add_log_record_processor(
        BatchLogRecordProcessor(exporter)
    )

    handler = LoggingHandler(
        level=logging.INFO,
        logger_provider=provider
    )

    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)