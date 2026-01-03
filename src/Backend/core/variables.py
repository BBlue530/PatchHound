import os
from reportlab.lib import colors

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

patchhound_version = "0.1.32"

GRYPE_VERSION = "0.104.1"
COSIGN_VERSION = "2.5.3"

app_config_path = "app-config.yaml"

# Ruleset descriptions from Semgrep Registry documentation
SEMGREP_RULESETS = {
    # Language oriented rulesets
    "p/python": "Python-specific rules targeting security, correctness, anti-patterns, common library misuse, and idioms. Applies to Python codebases.",
    "p/javascript": "JavaScript rules (core language) covering typical vulnerabilities and code quality issues.",
    "p/typescript": "TypeScript specific rules for TS syntax and patterns.",
    "p/nodejs": "Node.js ecosystem patterns (security and patterns relevant to Node).",
    "p/react": "React framework-focused patterns (security, best practices, component anti-patterns).",
    "p/eslint": "Rules designed to overlap with JavaScript linting rules (similar to ESLint).",
    "p/expressjs": "Framework subsets for JS/TS ecosystems (Express.js, Next.js, Koa).",
    "p/nextjs": "Framework subsets for JS/TS ecosystems (Express.js, Next.js, Koa).",
    "p/koa": "Framework subsets for JS/TS ecosystems (Express.js, Next.js, Koa).",
    "p/java": "Java rules covering common API misuse, security, and code patterns.",
    "p/go": "Go language rules (e.g., error handling, concurrency hazards, misuse).",
    "p/php": "PHP language rules (security patterns, common PHP pitfalls).",
    "p/ruby": "Language rules for other supported ecosystems.",
    "p/swift": "Language rules for other supported ecosystems.",
    "p/csharp": "Language rules for other supported ecosystems.",
    "p/rust": "Language rules for other supported ecosystems.",
    "p/scala": "Language rules for other supported ecosystems.",
    "p/bash": "Shell script rules to catch quoting bugs, injection patterns, unsafe expansions.",
    "p/terraform": "Terraform infrastructure-as-code rules (security, configuration drift, misconfig).",
    "p/kubernetes": "IaC and container config rules (policy & security checks).",
    "p/dockerfile": "IaC and container config rules (policy & security checks).",
    # Security and best practice packs
    "p/ci": "CI-friendly ruleset targeting high-confidence issues suitable for gating builds or PR checks. Recommended for fast, low-noise scans.",
    "p/security-audit": "Deep security audit ruleset detecting subtle, less obvious vulnerabilities; more noise but more coverage. Good for manual review or scheduled audits.",
    "p/default": "Semgreps default group of recommended rules; a good starter point.",
    "p/comment": "Advisory rules that emit comments or informational findings rather than blocking issues.",
    "p/owasp-top-ten": "Rules targeting common OWASP Top 10 web security categories.",
    "p/cwe-top-25": "Rules mapped to the CWEs (Common Weakness Enumeration) list.",
    "p/all": "(Registry identifier) Runs all public rules in the Semgrep Registry heavy and noisy.",
}