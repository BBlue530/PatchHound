from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from flask import abort
import json
import os
from utils.helpers import safe_text
from core.variables import all_repo_scans_folder, all_resources_folder

def summary_to_pdf(organization_decoded, current_repo_decoded, timestamp_decoded):
    base_dir = os.path.join(all_resources_folder, all_repo_scans_folder, organization_decoded, current_repo_decoded, timestamp_decoded)

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

    elements.append(Paragraph("Exclusions", styles["Heading2"]))

    for excl in summary_report.get("exclusions", []):
        elements.append(Paragraph(f"<b>Source:</b> {safe_text(excl.get('source'))}", wrap_style))
        elements.append(Paragraph(f"<b>Severity:</b> {safe_text(excl.get('severity'))}", wrap_style))
        elements.append(Paragraph(f"<b>Package:</b> {safe_text(excl.get('package'))}", wrap_style))
        elements.append(Paragraph(f"<b>Version:</b> {safe_text(excl.get('version'))}", wrap_style))
        elements.append(Paragraph(f"<b>Title:</b> {safe_text(excl.get('title') or excl.get('description'))}", wrap_style))
        elements.append(Paragraph(f"<b>Comment:</b> {safe_text(excl.get('comment'))}", wrap_style))
        elements.append(Spacer(1, 12))

    elements.append(Paragraph("CISA KEV Prioritized Vulnerabilities", styles["Heading2"]))
    
    for kev in summary_report.get("kev_vulnerabilities", []):
        elements.append(Paragraph(f"<b>ID:</b> {safe_text(kev.get('id'))}", wrap_style))
        elements.append(Paragraph(f"<b>Severity:</b> {safe_text(kev.get('severity'))}", wrap_style))
        elements.append(Paragraph(f"<b>Title:</b> {safe_text(kev.get('title') or kev.get('description'))}", wrap_style))
        elements.append(Paragraph(f"<b>Vendor:</b> {safe_text(kev.get('vendor'))}", wrap_style))
        elements.append(Paragraph(f"<b>Product:</b> {safe_text(kev.get('product'))}", wrap_style))
        elements.append(Paragraph(f"<b>Required Action:</b> {safe_text(kev.get('required_action'))}", wrap_style))
        elements.append(Paragraph(f"<b>Added Date:</b> {safe_text(kev.get('kev_added_date'))}", wrap_style))
        elements.append(Paragraph(f"<b>Due Date:</b> {safe_text(kev.get('kev_due_date'))}", wrap_style))
        elements.append(Paragraph(f"<b>Link:</b> {safe_text(kev.get('link'))}", wrap_style))
        elements.append(Spacer(1, 12))

    elements.append(Paragraph("Vulnerabilities", styles["Heading2"]))

    for vuln in summary_report.get("vulnerabilities", []):
        if vuln.get('source') == "grype":
            elements.append(Paragraph(f"<b>Source:</b> {safe_text(vuln.get('source'))}", wrap_style))
            elements.append(Paragraph(f"<b>ID:</b> {safe_text(vuln.get('id'))}", wrap_style))
            elements.append(Paragraph(f"<b>Severity:</b> {safe_text(vuln.get('severity'))}", wrap_style))
            elements.append(Paragraph(f"<b>Package:</b> {safe_text(vuln.get('package'))}", wrap_style))
            elements.append(Paragraph(f"<b>Version:</b> {safe_text(vuln.get('version'))}", wrap_style))
            elements.append(Paragraph(f"<b>Description:</b> {safe_text(vuln.get('description'))}", wrap_style))
            elements.append(Paragraph(f"<b>Link:</b> {safe_text(vuln.get('link'))}", wrap_style))
            elements.append(Spacer(1, 12))

        elif vuln.get('source') == "semgrep":
            elements.append(Paragraph(f"<b>Source:</b> {safe_text(vuln.get('source'))}", wrap_style))
            elements.append(Paragraph(f"<b>ID:</b> {safe_text(vuln.get('id'))}", wrap_style))
            elements.append(Paragraph(f"<b>Path:</b> {safe_text(vuln.get('path'))}", wrap_style))
            elements.append(Paragraph(f"<b>Line:</b> {safe_text(vuln.get('line'))}", wrap_style))
            elements.append(Paragraph(f"<b>Message:</b> {safe_text(vuln.get('message'))}", wrap_style))
            elements.append(Paragraph(f"<b>Severity:</b> {safe_text(vuln.get('severity'))}", wrap_style))
            elements.append(Spacer(1, 12))
            
        elif vuln.get('source') == "trivy_vulnerability":
            elements.append(Paragraph(f"<b>Source:</b> {safe_text(vuln.get('source'))}", wrap_style))
            elements.append(Paragraph(f"<b>ID:</b> {safe_text(vuln.get('id'))}", wrap_style))
            elements.append(Paragraph(f"<b>Type:</b> {safe_text(vuln.get('type'))}", wrap_style))
            elements.append(Paragraph(f"<b>Package:</b> {safe_text(vuln.get('package'))}", wrap_style))
            elements.append(Paragraph(f"<b>Version:</b> {safe_text(vuln.get('version'))}", wrap_style))
            elements.append(Paragraph(f"<b>Severity:</b> {safe_text(vuln.get('severity'))}", wrap_style))
            elements.append(Paragraph(f"<b>Title:</b> {safe_text(vuln.get('title'))}", wrap_style))
            elements.append(Paragraph(f"<b>Link:</b> {safe_text(vuln.get('link'))}", wrap_style))
            elements.append(Spacer(1, 12))

        elif vuln.get('source') == "trivy_misconfiguration":
            elements.append(Paragraph(f"<b>Source:</b> {safe_text(vuln.get('source'))}", wrap_style))
            elements.append(Paragraph(f"<b>ID:</b> {safe_text(vuln.get('id'))}", wrap_style))
            elements.append(Paragraph(f"<b>Type:</b> {safe_text(vuln.get('type'))}", wrap_style))
            elements.append(Paragraph(f"<b>Title:</b> {safe_text(vuln.get('title'))}", wrap_style))
            elements.append(Paragraph(f"<b>Description:</b> {safe_text(vuln.get('description'))}", wrap_style))
            elements.append(Paragraph(f"<b>Resolution:</b> {safe_text(vuln.get('resolution'))}", wrap_style))
            elements.append(Paragraph(f"<b>Severity:</b> {safe_text(vuln.get('severity'))}", wrap_style))
            elements.append(Paragraph(f"<b>File:</b> {safe_text(vuln.get('file'))}", wrap_style))
            elements.append(Paragraph(f"<b>Links:</b> {safe_text(vuln.get('links'))}", wrap_style))
            elements.append(Spacer(1, 12))

        elif vuln.get('source') == "trivy_secret":
            elements.append(Paragraph(f"<b>Source:</b> {safe_text(vuln.get('source'))}", wrap_style))
            elements.append(Paragraph(f"<b>ID:</b> {safe_text(vuln.get('id'))}", wrap_style))
            elements.append(Paragraph(f"<b>Type:</b> {safe_text(vuln.get('type'))}", wrap_style))
            elements.append(Paragraph(f"<b>Title:</b> {safe_text(vuln.get('title'))}", wrap_style))
            elements.append(Paragraph(f"<b>Description:</b> {safe_text(vuln.get('description'))}", wrap_style))
            elements.append(Paragraph(f"<b>Severity:</b> {safe_text(vuln.get('severity'))}", wrap_style))
            elements.append(Paragraph(f"<b>File:</b> {safe_text(vuln.get('file'))}", wrap_style))
            elements.append(Paragraph(f"<b>Message:</b> {safe_text(vuln.get('message'))}", wrap_style))
            elements.append(Spacer(1, 12))
    
    elements.append(Paragraph("Packages", styles["Heading2"]))

    for vuln in summary_report.get("packages", []):
        elements.append(Paragraph(f"<b>ID:</b> {safe_text(vuln.get('id'))}", wrap_style))
        elements.append(Paragraph(f"<b>Name:</b> {safe_text(vuln.get('name'))}", wrap_style))
        elements.append(Paragraph(f"<b>Version:</b> {safe_text(vuln.get('version'))}", wrap_style))
        elements.append(Paragraph(f"<b>Type:</b> {safe_text(vuln.get('type'))}", wrap_style))
        elements.append(Paragraph(f"<b>PURL:</b> {safe_text(vuln.get('purl'))}", wrap_style))
        elements.append(Paragraph(f"<b>CPE:</b> {safe_text(vuln.get('cpe'))}", wrap_style))
        elements.append(Paragraph(f"<b>Package type:</b> {safe_text(vuln.get('package_type'))}", wrap_style))
        elements.append(Paragraph(f"<b>Language:</b> {safe_text(vuln.get('language'))}", wrap_style))
        elements.append(Paragraph(f"<b>Metadata type:</b> {safe_text(vuln.get('metadata_type'))}", wrap_style))
        elements.append(Paragraph(f"<b>Found by:</b> {safe_text(vuln.get('found_by'))}", wrap_style))
        elements.append(Spacer(1, 12))

    doc.build(elements)
    print(f"[+] PDF report saved as: {pdf_filename_path}")
    return pdf_filename_path