grype_exclusions_vulnerabilities_table_data_headers = [
    "ID",
    "Source",
    "Description",

    "Severity",

    "Type",

    "Score",
    "CVSS Vector",
    "Package",
    "Version",
    "Link",

    "Scope",
    "Comment",
]

grype_excl_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity

    50,  # Type

    25,  # Score
    35,  # CVSS Vector
    30,  # Package
    25,  # Version
    35,  # Link
    
    50,  # Scope
    50,  # Comment
]

def fetch_grype_exclusions_vulnerabilities_table_data():
    return [grype_exclusions_vulnerabilities_table_data_headers.copy()]

trivy_vulnerability_exclusions_vulnerabilities_table_data_headers = [
    "ID",
    "Source",
    "Description",

    "Severity",

    "Type",

    "Score",
    "CVSS Vector",
    "Package",
    "Version",
    "Link",

    "Scope",
    "Comment",
]

trivy_vulnerability_excl_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity

    50,  # Type

    25,  # Score
    35,  # CVSS Vector
    30,  # Package
    25,  # Version
    35,  # Link
    
    50,  # Scope
    50,  # Comment
]

def fetch_trivy_vulnerability_exclusions_vulnerabilities_table_data():
    return [trivy_vulnerability_exclusions_vulnerabilities_table_data_headers.copy()]

semgrep_exclusions_vulnerabilities_table_data_headers = [
    "ID",
    "Source",
    "Description",

    "Severity",

    "Type",

    "Path",
    "Line",

    "Scope",
    "Comment",
]

semgrep_excl_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity

    50,  # Type

    150, # Path
    50, # Line
    
    50,  # Scope
    50,  # Comment
]

def fetch_semgrep_exclusions_vulnerabilities_table_data():
    return [semgrep_exclusions_vulnerabilities_table_data_headers.copy()]

trivy_misconfiguration_exclusions_vulnerabilities_table_data_headers = [
    "ID",
    "Source",
    "Description",

    "Severity",

    "Type",

    "Title",
    "Resolution",
    "File",
    "Links",

    "Scope",
    "Comment",
]

trivy_misconfiguration_excl_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity

    50,  # Type

    50,   # Title
    50,  # Resolution
    50,   # File
    50,   # Links
    
    50,   # Scope
    50,   # Comment
]

def fetch_trivy_misconfiguration_exclusions_vulnerabilities_table_data():
    return [trivy_misconfiguration_exclusions_vulnerabilities_table_data_headers.copy()]

trivy_secret_exclusions_vulnerabilities_table_data_headers = [
    "ID",
    "Source",
    "Description",

    "Severity",

    "Type",

    "Title",
    "File",
    "Message",

    "Scope",
    "Comment",
]

trivy_secret_excl_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity

    50,  # Type

    50,  # Title
    50, # File
    100, # Message
    
    50,  # Scope
    50,  # Comment
]

def fetch_trivy_secret_exclusions_vulnerabilities_table_data():
    return [trivy_secret_exclusions_vulnerabilities_table_data_headers.copy()]

exclusions_vulnerabilities_table_data_headers = [
    "ID",
    "Source",
    "Description",

    "Severity",

    "Type",

    "Score",
    "CVSS vector",
    "Found by",
    "Package",
    "Version",
    "Link",

    "Scope",
    "Comment",
]

excl_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity

    50,  # Type

    25,  # Score
    35,  # CVSS vector
    30,  # Found by
    30,  # Package
    30,  # Version
    50,  # Link
    
    50,  # Scope
    50,  # Comment
]

def fetch_exclusions_vulnerabilities_table_data():
    return [exclusions_vulnerabilities_table_data_headers.copy()]

kev_vulnerabilities_table_data_headers = [
    "ID",
    "Source",
    "Description",

    "Severity",

    "Type",

    "Priority",
    "Vendor",
    "Title",
    "Required action",
    "Added date",
    "Due date",
    "Link",
]

kev_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity

    50,  # Type

    25,  # Priority
    25,  # Vendor
    25,  # Title
    75,  # Required action
    25,  # Added date
    25,  # Due date
    100, # Link
]

def fetch_kev_vulnerabilities_table_data():
    return [kev_vulnerabilities_table_data_headers.copy()]

new_vulnerabilities_table_data_headers = [
    "ID",
    "Source",
    "Description",
    
    "Severity",

    "Type",
    
    "Score",
    "CVSS vector",
    "Found timestamp",
    "Package",
    "Version",
    "Link",
]

new_vuln_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity

    50,  # Type

    25,  # Score
    50,  # CVSS vector
    50,  # Found timestamp
    50,  # Package
    25,  # Version
    100, # Link
]

def fetch_new_vulnerabilities_table_data():
    return [new_vulnerabilities_table_data_headers.copy()]

vulnerabilities_grype_table_data_headers = [
    "ID",
    "Source",
    "Description",

    "Severity",

    "Type",

    "Score",
    "CVSS vector",
    "Package",
    "Version",
    "Link",
]

grype_vuln_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity

    50,  # Type

    50,  # Score
    50,  # CVSS vector
    50,  # Package
    50,  # Version
    100, # Link
]

def fetch_vulnerabilities_grype_table_data():
    return [vulnerabilities_grype_table_data_headers.copy()]

vulnerabilities_semgrep_table_data_headers = [
    "ID",
    "Source",
    "Description",

    "Severity",

    "Type",

    "Path",
    "Line",
]

semgrep_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity
    
    50,  # Type

    200, # Path
    100, # Line
]

def fetch_vulnerabilities_semgrep_table_data():
    return [vulnerabilities_semgrep_table_data_headers.copy()]

vulnerabilities_trivy_table_data_headers = [
    "ID",
    "Source",
    "Description",

    "Severity",

    "Type",

    "Score",
    "CVSS vector",
    "Package",
    "Version",
    "Link",
]

trivy_vuln_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity

    50,  # Type
    
    25,  # Score
    100, # CVSS vector
    50,  # Package
    25,  # Version
    100, # Link
]

def fetch_vulnerabilities_trivy_table_data():
    return [vulnerabilities_trivy_table_data_headers.copy()]

misconfigurations_trivy_table_data_headers = [
    "ID",
    "Source",
    "Description",

    "Severity",

    "Type",

    "Title",
    "Resolution",
    "File",
    "Links",
]

trivy_misconfig_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity
    
    50,  # Type

    50,  # Title
    100, # Resolution
    50,  # File
    100, # Links
]

def fetch_misconfigurations_trivy_table_data():
    return [misconfigurations_trivy_table_data_headers.copy()]

secrets_trivy_table_data_headers = [
    "ID",
    "Source",
    "Description",

    "Severity",

    "Type",

    "Title",
    "File",
    "Message",
]

trivy_secrets_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity
    
    50,  # Type

    50,  # Title
    100, # File
    150, # Message
]

def fetch_secrets_trivy_table_data():
    return [secrets_trivy_table_data_headers.copy()]

packages_table_data_headers = [
    "ID",
    "Source",
    # Description?

    "Name",
    "Version",
    "Type",
    "PURL",
    "CPE",
    "Package type",
    "Language",
    "Metadata type",
    "Found by",
    "Locations",
]

packages_col_widths = [
    50,  # ID
    50,  # Source
    # Description?

    50,  # Name
    35,  # Version
    35,  # Type
    45,  # PURL
    60,  # CPE
    60,  # Package type
    45,  # Language
    60,  # Metadata type
    60,  # Found by
    50,  # Locations
]

def fetch_packages_table_data():
    return [packages_table_data_headers.copy()]