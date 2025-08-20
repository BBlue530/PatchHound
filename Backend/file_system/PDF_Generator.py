from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from flask import abort
import json
import os
from utils.helpers import safe_text
from core.variables import all_repo_scans_folder

def summary_to_pdf(organization_decoded, current_repo_decoded, timestamp_decoded):
    base_dir = os.path.join(all_repo_scans_folder, organization_decoded, current_repo_decoded, timestamp_decoded)

    if not os.path.isdir(base_dir):
        abort(404, description=f"Directory not found: {base_dir}")
    
    pdf_filename_path = os.path.join(base_dir, f"{current_repo_decoded}_pdf_summary_report.pdf")
    summary_report_path = os.path.join(base_dir, f"{current_repo_decoded}_summary_report.json")

    with open(summary_report_path, "r") as f:
        summary_report = json.load(f)

    styles = getSampleStyleSheet()
    wrap_style = ParagraphStyle(
        name="wrap",
        fontName="Helvetica",
        fontSize=8,
        leading=10,
    )

    doc = SimpleDocTemplate(pdf_filename_path, pagesize=A4)
    elements = []

    elements.append(Paragraph("Security Scan Summary", styles["Title"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Vulnerabilities", styles["Heading2"]))
    vuln_data = [["Source", "Severity", "Package", "Version", "Title/Description", "Link"]]

    for vuln in summary_report.get("vulnerabilities", []):
        vuln_data.append([
            Paragraph(safe_text(vuln.get("source")), wrap_style),
            Paragraph(safe_text(vuln.get("severity")), wrap_style),
            Paragraph(safe_text(vuln.get("package")), wrap_style),
            Paragraph(safe_text(vuln.get("version")), wrap_style),
            Paragraph(safe_text(vuln.get("title") or vuln.get("description")), wrap_style),
            Paragraph(safe_text(vuln.get("link")), wrap_style),
        ])

    vuln_table = Table(vuln_data, repeatRows=1)
    vuln_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]))
    elements.append(vuln_table)
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Exclusions", styles["Heading2"]))
    excl_data = [["Source", "Severity", "Package", "Version", "Title/Description", "Comment"]]

    for excl in summary_report.get("exclusions", []):
        excl_data.append([
            Paragraph(safe_text(excl.get("source")), wrap_style),
            Paragraph(safe_text(excl.get("severity")), wrap_style),
            Paragraph(safe_text(excl.get("package")), wrap_style),
            Paragraph(safe_text(excl.get("version")), wrap_style),
            Paragraph(safe_text(excl.get("title") or excl.get("description")), wrap_style),
            Paragraph(safe_text(excl.get("comment")), wrap_style),
        ])

    excl_table = Table(excl_data, repeatRows=1)
    excl_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]))
    elements.append(excl_table)

    doc.build(elements)
    print(f"PDF report saved as: {pdf_filename_path}")
    return pdf_filename_path