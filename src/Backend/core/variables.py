import os

kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

kev_catalog = "kev_catalog.json"

all_resources_folder = "resource_data"
all_repo_scans_folder = "scan_data"
all_image_signature_folder = "image_signature"
all_base_image_signature_folder = "base_image_signature"

service_log_path = os.path.join(all_resources_folder, "log_data", "service_logs.json")

scheduled_event_commit_sha = "Null"
scheduled_event_commit_author = "Daily Scan"

local_bin = os.path.expanduser("~/.local/bin")
env = os.environ.copy()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR_PATH = os.path.join(BASE_DIR, "..", all_resources_folder, "database")
DB_PATH = os.path.join(DB_DIR_PATH, "patchhound_db.sqlite")
db_path = os.path.normpath(DB_PATH)

secret_storage = "secrets.json"
length=32
secret_types = ["api_key", "jwt_key", "cosign_key"]

patchhound_version = "0.1.43"

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

# File ending names
syft_sbom_path_ending = "_syft_sbom_cyclonedx.json"
semgrep_sast_report_path_ending = "_semgrep_sast_report.json"
trivy_report_path_ending = "_trivy_report.json"
grype_path_ending = "_grype_vulns_cyclonedx.json"
prio_path_ending = "_prio_vuln_data.json"
summary_report_path_ending = "_summary_report.json"
audit_trail_path_ending = "_audit_trail.json"

exclusions_file_path_ending = "_exclusions_file.json"
repo_history_path_ending = "_repo_history.json"

att_sig_path_ending = "_att.sig"
attestation_path_ending = ".att"
sig_path_ending = ".sig"

digest_path_ending = "_digest.txt"

cosign_key_path_ending = ".key"
cosign_pub_path_ending = ".pub"
alert_path_ending = "_alert.json"
fail_on_severity_path_ending = "_fail_on_severity.json"

pdf_filename_path_ending = "_pdf_summary_report.pdf"

# Rule names for rescan alert threshold
all_not_excluded_vulnerabilities = "all_not_excluded_vulnerabilities"
all_new_vulnerabilities = "all_new_vulnerabilities"
all_vulnerabilities = "all_vulnerabilities"