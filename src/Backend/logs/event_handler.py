import os
from datetime import datetime, timezone
from logs.audit_trail import audit_trail_event
from logs.export_logs import log_exporter
from core.variables import log_type_info, log_type_debug, log_type_error

from core.variables import *

def event(audit_trail, new_event):
    if new_event.get("level") == log_type_error:
        audit_trail = handle_event(audit_trail, new_event)
    elif os.environ["log_level"] == log_type_debug:
        audit_trail = handle_event(audit_trail, new_event)
    elif new_event.get("level") == log_type_info:
        audit_trail = handle_event(audit_trail, new_event)
    return audit_trail

def handle_event(audit_trail, new_event):
    new_event["service_timestamp"] = datetime.now(timezone.utc).isoformat()
    # Need improved check to if the audit trail is suppose to be populated
    if audit_trail is not False:
        audit_trail = audit_trail_event(audit_trail, new_event)
    log_exporter(new_event)
    print(new_event)
    return audit_trail