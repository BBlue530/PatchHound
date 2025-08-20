from flask import Flask, request, jsonify, send_file
import tempfile
import subprocess
import os
import json
from apscheduler.schedulers.background import BackgroundScheduler
import threading
import io
from datetime import datetime
from file_system.file_handling import save_scan_files
from file_system.pdf_generator import summary_to_pdf
from file_system.image_signature import sign_image_digest, verify_image_digest
from utils.schedule_handling import scheduled_event
from utils.jwt_path import jwt_path_to_resources, decode_jwt_path_to_resources
from file_system.resource_handling import get_resources, list_resources
from database.validate_token import validate_token
from database.create_db import create_database
from database.create_key import create_key
from database.key_status import enable_key, disable_key
from validation.check_format import check_json_format
from vuln_scan.kev_catalog import compare_kev_catalog
from core.system import install_tools
from validation.secrets_manager import verify_api_key, generate_secrets
from core.variables import version

# Route blueprints
from routes.generate_pdf import pdf_bp
from routes.health_check import health_bp
from routes.image_handling import image_bp
from routes.resource_handling import resource_bp
from routes.scan_sbom import scan_sbom_bp
from routes.token_key_handling import token_key_bp

app = Flask(__name__)
# Dont think i need this anymore but scared to remove it for now since its working like it should
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

app.register_blueprint(pdf_bp)
app.register_blueprint(health_bp)
app.register_blueprint(image_bp)
app.register_blueprint(resource_bp)
app.register_blueprint(scan_sbom_bp)
app.register_blueprint(token_key_bp)

install_tools()
generate_secrets()
scheduled_event()
create_database()

scheduler = BackgroundScheduler()
scheduler.add_job(scheduled_event, 'cron', hour=3, minute=0)
scheduler.start()