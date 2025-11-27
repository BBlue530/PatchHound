import os

kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

kev_catalog = "kev_catalog.json"

all_resources_folder = "resources"
all_repo_scans_folder = "all_scans"
all_image_signature_folder = "all_image_signature"
all_base_image_signature_folder = "all_base_image_signature"

scheduled_event_commit_sha = "Null"
scheduled_event_commit_author = "Daily Scan"

local_bin = os.path.expanduser("~/.local/bin")
env = os.environ.copy()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "database", "keys_db.sqlite")
db_path = os.path.normpath(DB_PATH)

secret_storage = "secrets.json"
length=32
secret_types = ["api_key", "jwt_key", "cosign_key"]

version = "0.1.10"

GRYPE_VERSION = "0.104.1"
COSIGN_VERSION = "2.5.3"