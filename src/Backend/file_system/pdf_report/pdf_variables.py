from reportlab.lib import colors

SEVERITY_COLORS = {
    # Semgrep warnings
    "error": colors.red,
    "warning": colors.orange,
    # Normal severity
    "critical": colors.red,
    "high": colors.orange,
    "medium": colors.yellow,
    "low": colors.lightgreen,
}