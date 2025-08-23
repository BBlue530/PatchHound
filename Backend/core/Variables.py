import os

kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

kev_catalog = "kev_catalog.json"
all_repo_scans_folder = "all_scans"

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

version = "0.1.1"

GRYPE_VERSION = "0.68.0"
COSIGN_VERSION = "2.5.3"