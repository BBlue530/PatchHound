exclusions_vulnerabilities_table_data = [
    [
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
]
exclusions_vulnerabilities_severity_rows = []

excl_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity

    25,  # Type

    25,    # Score
    50,    # CVSS vector
    40,    # Found by
    40,    # Package
    40,    # Version
    50,    # Link
    
    25,    # Scope
    55,    # Comment
]

kev_vulnerabilities_table_data = [
    [
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
]
kev_vulnerabilities_severity_rows = []

kev_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity

    50,  # Type

    25,  # Priority
    25,  # Vendor
    25,  # Title
    75, # Required action
    25,  # Added date
    25,  # Due date
    100, # Link
]

new_vulnerabilities_table_data = [
    [
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
]
new_vulnerabilities_severity_rows = []

new_vuln_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity

    50,  # Type

    25,    # Score
    50,    # CVSS vector
    50,    # Found timestamp
    50,    # Package
    25,    # Version
    100,    # Link

]

vulnerabilities_grype_table_data = [
    [
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
]
vulnerabilities_grype_severity_rows = []

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
    100,  # Link
]

vulnerabilities_semgrep_table_data = [
    [
        "ID",
        "Source",
        "Description",

        "Severity",

        "Type",

        "Path",
        "Line",
    ]
]
vulnerabilities_semgrep_severity_rows = []

semgrep_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity
    
    50,  # Type

    200, # Path
    100, # Line
]

vulnerabilities_trivy_table_data = [
    [
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
]
vulnerabilities_trivy_severity_rows = []

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

misconfigurations_trivy_table_data = [
    [
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
]
misconfigurations_trivy_severity_rows = []

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

secrets_trivy_table_data = [
    [
        "ID",
        "Source",
        "Description",

        "Severity",

        "Type",

        "Title",
        "File",
        "Message",
    ]
]
secrets_trivy_severity_rows = []

trivy_secrets_col_widths = [
    50,  # ID
    50,  # Source
    100, # Description

    50,  # Severity
    
    50,  # Type

    50, # Title
    100, # File
    150, # Message
]

packages_table_data = [
    [
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