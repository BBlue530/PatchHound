from reportlab.lib import colors
from reportlab.platypus import Table
from core.variables import SEMGREP_RULESETS
from file_system.pdf_report.pdf_variables import SEVERITY_COLORS

def normalize_semgrep_ruleset(semgrep_ruleset_raw):
    if not semgrep_ruleset_raw:
        return []
    
    normalized_semgrep_rulesets = []

    for ruleset in semgrep_ruleset_raw:
        ruleset_normalized = ruleset.replace("--config=", "")

        ruleset_description = SEMGREP_RULESETS.get(ruleset_normalized, "Unknown Semgrep ruleset")

        normalized_semgrep_rulesets.append({
            "name": ruleset_normalized,
            "description": ruleset_description
        })

    return normalized_semgrep_rulesets

def build_data_table(new_table_data, new_severity_rows, table_widths):
    if not new_table_data or len(new_table_data) < 2:
        return None
    
    new_table_build = Table(
        new_table_data,
        repeatRows=1,
        colWidths=table_widths,
    )

    new_table_build.setStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.transparent]),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),

        ("VALIGN", (0, 1), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),

        ("ALIGN", (1, 1), (1, -1), "CENTER"),

        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
    ])

    if new_severity_rows:
        for row_index, severity in new_severity_rows:
            color = SEVERITY_COLORS.get(severity.lower())

            if color:
                new_table_build.setStyle([
                    ("BACKGROUND", (3, row_index), (3, row_index), color),
                    ("TEXTCOLOR", (3, row_index), (3, row_index), colors.black),
                ])
    
    return new_table_build