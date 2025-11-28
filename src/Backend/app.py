from flask import Flask
from apscheduler.schedulers.background import BackgroundScheduler
from utils.schedule_handling import scheduled_event
from database.create_db import create_database
from core.system import install_tools
from validation.secrets_manager import generate_secrets, verify_secrets

# Route blueprints
from routes.generate_pdf import pdf_bp
from routes.health_check import health_bp
from routes.image_handling import image_bp
from routes.resource_handling import resource_bp
from routes.scan_sbom import scan_sbom_bp
from routes.token_key_handling import token_key_bp

app = Flask(__name__)

app.register_blueprint(pdf_bp)
app.register_blueprint(health_bp)
app.register_blueprint(image_bp)
app.register_blueprint(resource_bp)
app.register_blueprint(scan_sbom_bp)
app.register_blueprint(token_key_bp)

if __name__ == "__main__":
    install_tools()
    generate_secrets()
    verify_secrets()
    scheduled_event()
    create_database()

    scheduler = BackgroundScheduler()
    scheduler.add_job(scheduled_event, 'cron', hour=3, minute=0)
    scheduler.start()
    app.run(host="0.0.0.0", port=8080, debug=True)