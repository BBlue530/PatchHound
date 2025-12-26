from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from datetime import datetime
from flask import abort
import json
import os
from utils.helpers import safe_text
from external_storage.external_storage_get import get_resources_external_storage_internal_use
from core.variables import all_repo_scans_folder, all_resources_folder

def summary_to_pdf(organization_decoded, current_repo_decoded, timestamp_decoded):
    base_dir = os.path.join(all_resources_folder, all_repo_scans_folder, organization_decoded, current_repo_decoded, timestamp_decoded)
    
    pdf_filename_path = os.path.join(base_dir, f"{current_repo_decoded}_pdf_summary_report.pdf")
    summary_report_path = os.path.join(base_dir, f"{current_repo_decoded}_summary_report.json")

    if os.environ.get("external_storage_enabled", "False").lower() == "true":
        memory_file = get_resources_external_storage_internal_use(summary_report_path)
        summary_report = json.load(memory_file)
    else:
        if not os.path.isdir(base_dir):
            abort(404, description=f"Directory not found: {base_dir}")

        with open(summary_report_path, "r") as f:
            summary_report = json.load(f)
    
    current_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    report_generated_date = datetime.strptime(current_timestamp, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d")
    scan_generated_date = datetime.strptime(timestamp_decoded, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d")

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
    elements.append(Paragraph(f"<b>Scan date:</b> {scan_generated_date}", wrap_style))
    elements.append(Paragraph(f"<b>Report generated date:</b> {report_generated_date}", wrap_style))
    elements.append(Spacer(1, 12))

    counters = summary_report.get("counters")

    elements.append(Paragraph("Stats", styles["Heading2"]))
    elements.append(Paragraph(f"<b>Packages found:</b> {counters.get('package_counter')}", wrap_style))
    elements.append(Paragraph(f"<b>KEV vulnerabilities found:</b> {counters.get('kev_vuln_counter')}", wrap_style))
    elements.append(Paragraph(f"<b>Excluded vulnerabilities found:</b> {counters.get('excluded_kev_vuln_counter')}", wrap_style))

    elements.append(Paragraph(f"<b>Excluded vulnerabilities found:</b> {counters.get('excluded_vuln_counter')}", wrap_style))
    elements.append(Paragraph(f"<b>Vulnerabilities found:</b> {counters.get('vuln_counter')}", wrap_style))

    elements.append(Paragraph(f"<b>Excluded misconfigurations found:</b> {counters.get('excluded_misconf_counter')}", wrap_style))
    elements.append(Paragraph(f"<b>Misconfigurations found:</b> {counters.get('misconf_counter')}", wrap_style))

    elements.append(Paragraph(f"<b>Excluded exposed secrets found:</b> {counters.get('excluded_exposed_secret_counter')}", wrap_style))
    elements.append(Paragraph(f"<b>Exposed secrets found:</b> {counters.get('exposed_secret_counter')}", wrap_style))
    elements.append(Spacer(1, 12))

    tool_version = summary_report.get("tool_version")

    elements.append(Paragraph("Tool versions", styles["Heading2"]))
    elements.append(Paragraph(f"<b>Syft:</b> {tool_version.get('syft_version')}", wrap_style))
    elements.append(Paragraph(f"<b>Semgrep:</b> {tool_version.get('semgrep_version')}", wrap_style))
    elements.append(Paragraph(f"<b>Trivy:</b> {tool_version.get('trivy_version')}", wrap_style))
    elements.append(Paragraph(f"<b>Grype:</b> {tool_version.get('grype_version')}", wrap_style))
    elements.append(Paragraph(f"<b>Cosign:</b> {tool_version.get('cosign_version')}", wrap_style))
    elements.append(Paragraph(f"<b>PatchHound:</b> {tool_version.get('patchhound_version')}", wrap_style))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Exclusions", styles["Heading2"]))

    exclusions = summary_report.get("exclusions")

    if not exclusions:
        elements.append(Paragraph("<b>No exclusions found</b>", wrap_style))
    else:
        for excl in summary_report.get("exclusions", []):
            if excl:
                excl_link = None
                if excl.get('link'):
                    excl_link = safe_text(excl.get('link'))
                
                if excl_link:
                    elements.append(Paragraph(f'<b>ID:</b> <link href="{excl_link}">{safe_text(excl.get("id"))}</link>', wrap_style))
                else:
                    elements.append(Paragraph(f"<b>ID:</b> {safe_text(excl.get('id'))}", wrap_style))

                if excl.get('score'):
                    elements.append(Paragraph(f"<b>Score:</b> {safe_text(vuln.get('score'))}", wrap_style))
                    elements.append(Paragraph(f"<b>CVSS vector:</b> {safe_text(vuln.get('cvss_vector'))}", wrap_style))
                elements.append(Paragraph(f"<b>Severity:</b> {safe_text(excl.get('severity'))}", wrap_style))

                elements.append(Paragraph(f"<b>Source:</b> {safe_text(excl.get('source'))}", wrap_style))
                elements.append(Paragraph(f"<b>Found by:</b> {safe_text(excl.get('vuln_source'))}", wrap_style))
                elements.append(Paragraph(f"<b>Type:</b> {safe_text(excl.get('type'))}", wrap_style))
                elements.append(Paragraph(f"<b>Description:</b> {safe_text(excl.get('description'))}", wrap_style))

                if excl.get('package'):
                    elements.append(Paragraph(f"<b>Package:</b> {safe_text(excl.get('package'))}", wrap_style))
                if excl.get('version'):
                    elements.append(Paragraph(f"<b>Version:</b> {safe_text(excl.get('version'))}", wrap_style))
                if excl_link:
                    elements.append(Paragraph(f'<b>Link:</b> <link href="{excl_link}">{excl_link}</link>', wrap_style))

                elements.append(Paragraph(f"<b>Scope:</b> {safe_text(excl.get('scope'))}", wrap_style))
                elements.append(Paragraph(f"<b>Comment:</b> {safe_text(excl.get('public_comment'))}", wrap_style))
                elements.append(Spacer(1, 12))

    elements.append(Paragraph("CISA KEV Prioritized Vulnerabilities", styles["Heading2"]))

    kev_vulnerabilities = summary_report.get("kev_vulnerabilities")

    if not kev_vulnerabilities:
        elements.append(Paragraph(f"<b>No kev vulnerabilities found</b>", wrap_style))
    else:
        for kev_vuln in summary_report.get("kev_vulnerabilities", []):
            if kev_vuln:
                kev_link = None
                kev_link = safe_text(kev_vuln.get('link'))

                elements.append(Paragraph(f'<b>ID:</b> <link href="{kev_link}">{safe_text(kev_vuln.get("id"))}</link>', wrap_style))
                elements.append(Paragraph(f"<b>Severity:</b> {safe_text(kev_vuln.get('severity'))}", wrap_style))
                
                elements.append(Paragraph(f"<b>Source:</b> {safe_text(kev_vuln.get('source'))}", wrap_style))
                elements.append(Paragraph(f"<b>Type:</b> {safe_text(kev_vuln.get('type'))}", wrap_style))
                elements.append(Paragraph(f"<b>Description:</b> {safe_text(kev_vuln.get('description'))}", wrap_style))

                elements.append(Paragraph(f"<b>Priority:</b> {safe_text(kev_vuln.get('kev_priority'))}", wrap_style))
                elements.append(Paragraph(f"<b>Title:</b> {safe_text(kev_vuln.get('title'))}", wrap_style))
                elements.append(Paragraph(f"<b>Vendor:</b> {safe_text(kev_vuln.get('vendor'))}", wrap_style))
                elements.append(Paragraph(f"<b>Product:</b> {safe_text(kev_vuln.get('product'))}", wrap_style))

                elements.append(Paragraph(f"<b>Required action:</b> {safe_text(kev_vuln.get('required_action'))}", wrap_style))
                elements.append(Paragraph(f"<b>Added date:</b> {safe_text(kev_vuln.get('kev_added_date'))}", wrap_style))
                elements.append(Paragraph(f"<b>Due date:</b> {safe_text(kev_vuln.get('kev_due_date'))}", wrap_style))
                elements.append(Paragraph(f'<b>Link:</b> <link href="{kev_link}">{kev_link}</link>', wrap_style))
                elements.append(Spacer(1, 12))

    new_vulnerabilities = summary_report.get("new_vulnerabilities")

    if new_vulnerabilities:
        elements.append(Paragraph("New Found Vulnerabilities", styles["Heading2"]))
        for new_vuln in summary_report.get("new_vulnerabilities", []):
            if new_vuln:
                new_vuln_link = None
                new_vuln_link = safe_text(new_vuln.get('link'))

                elements.append(Paragraph(f'<b>ID:</b> <link href="{new_vuln_link}">{safe_text(new_vuln.get("id"))}</link>', wrap_style))
                elements.append(Paragraph(f"<b>Severity:</b> {safe_text(new_vuln.get('severity'))}", wrap_style))
                elements.append(Paragraph(f"<b>Score:</b> {safe_text(new_vuln.get('score'))}", wrap_style))
                elements.append(Paragraph(f"<b>CVSS vector:</b> {safe_text(new_vuln.get('cvss_vector'))}", wrap_style))

                elements.append(Paragraph(f"<b>Found timestamp:</b> {safe_text(new_vuln.get('vuln_found_timestamp'))}", wrap_style))

                elements.append(Paragraph(f"<b>Source:</b> {safe_text(new_vuln.get('source'))}", wrap_style))
                elements.append(Paragraph(f"<b>Type:</b> {safe_text(new_vuln.get('type'))}", wrap_style))
                elements.append(Paragraph(f"<b>Description:</b> {safe_text(new_vuln.get('description'))}", wrap_style))

                elements.append(Paragraph(f"<b>Package:</b> {safe_text(new_vuln.get('package'))}", wrap_style))
                elements.append(Paragraph(f"<b>Version:</b> {safe_text(new_vuln.get('version'))}", wrap_style))
                elements.append(Paragraph(f'<b>Link:</b> <link href="{new_vuln_link}">{new_vuln_link}</link>', wrap_style))
                elements.append(Spacer(1, 12))

    elements.append(Paragraph("Vulnerabilities", styles["Heading2"]))

    vulnerabilities = summary_report.get("vulnerabilities")

    if not vulnerabilities:
        elements.append(Paragraph(f"<b>No vulnerabilities found</b>", wrap_style))
    else:
        for vuln in summary_report.get("vulnerabilities", []):
            if vuln:

                if vuln.get('source') == "grype":
                    grype_link = None
                    grype_link = safe_text(vuln.get('link'))

                    elements.append(Paragraph(f'<b>ID:</b> <link href="{grype_link}">{safe_text(vuln.get("id"))}</link>', wrap_style))
                    elements.append(Paragraph(f"<b>Severity:</b> {safe_text(vuln.get('severity'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Score:</b> {safe_text(vuln.get('score'))}", wrap_style))
                    elements.append(Paragraph(f"<b>CVSS vector:</b> {safe_text(vuln.get('cvss_vector'))}", wrap_style))

                    elements.append(Paragraph(f"<b>Source:</b> {safe_text(vuln.get('source'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Type:</b> {safe_text(vuln.get('type'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Description:</b> {safe_text(vuln.get('description'))}", wrap_style))

                    elements.append(Paragraph(f"<b>Package:</b> {safe_text(vuln.get('package'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Version:</b> {safe_text(vuln.get('version'))}", wrap_style))
                    elements.append(Paragraph(f'<b>Link:</b> <link href="{grype_link}">{grype_link}</link>', wrap_style))
                    elements.append(Spacer(1, 12))

                elif vuln.get('source') == "semgrep":
                    elements.append(Paragraph(f"<b>ID:</b> {safe_text(vuln.get('id'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Severity:</b> {safe_text(vuln.get('severity'))}", wrap_style))

                    elements.append(Paragraph(f"<b>Source:</b> {safe_text(vuln.get('source'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Type:</b> {safe_text(vuln.get('type'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Description:</b> {safe_text(vuln.get('description'))}", wrap_style))

                    elements.append(Paragraph(f"<b>Path:</b> {safe_text(vuln.get('path'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Line:</b> {safe_text(vuln.get('line'))}", wrap_style))
                    elements.append(Spacer(1, 12))
                    
                elif vuln.get('source') == "trivy_vulnerability":
                    trivy_link = None
                    trivy_link = safe_text(vuln.get('link'))

                    elements.append(Paragraph(f'<b>ID:</b> <link href="{trivy_link}">{safe_text(vuln.get("id"))}</link>', wrap_style))
                    elements.append(Paragraph(f"<b>Severity:</b> {safe_text(vuln.get('severity'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Score:</b> {safe_text(vuln.get('score'))}", wrap_style))
                    elements.append(Paragraph(f"<b>CVSS vector:</b> {safe_text(vuln.get('cvss_vector'))}", wrap_style))

                    elements.append(Paragraph(f"<b>Source:</b> {safe_text(vuln.get('source'))}", wrap_style))

                    elements.append(Paragraph(f"<b>Type:</b> {safe_text(vuln.get('type'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Description:</b> {safe_text(vuln.get('description'))}", wrap_style))

                    elements.append(Paragraph(f"<b>Package:</b> {safe_text(vuln.get('package'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Version:</b> {safe_text(vuln.get('version'))}", wrap_style))
                    elements.append(Paragraph(f'<b>Link:</b> <link href="{trivy_link}">{trivy_link}</link>', wrap_style))
                    elements.append(Spacer(1, 12))

                elif vuln.get('source') == "trivy_misconfiguration":
                    elements.append(Paragraph(f"<b>ID:</b> {safe_text(vuln.get('id'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Severity:</b> {safe_text(vuln.get('severity'))}", wrap_style))

                    elements.append(Paragraph(f"<b>Source:</b> {safe_text(vuln.get('source'))}", wrap_style))

                    elements.append(Paragraph(f"<b>Type:</b> {safe_text(vuln.get('type'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Description:</b> {safe_text(vuln.get('description'))}", wrap_style))

                    elements.append(Paragraph(f"<b>Title:</b> {safe_text(vuln.get('title'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Resolution:</b> {safe_text(vuln.get('resolution'))}", wrap_style))
                    elements.append(Paragraph(f"<b>File:</b> {safe_text(vuln.get('file'))}", wrap_style))
                    
                    links = vuln.get('links', [])
                    if links:
                        elements.append(Paragraph("<b>Links:</b>", wrap_style))

                        for i, link in enumerate(links, 1):
                            safe_link = safe_text(link)
                            elements.append(Paragraph(f'{i}. <link href="{safe_link}">{safe_link}</link>', wrap_style))

                elif vuln.get('source') == "trivy_secret":
                    elements.append(Paragraph(f"<b>ID:</b> {safe_text(vuln.get('id'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Severity:</b> {safe_text(vuln.get('severity'))}", wrap_style))

                    elements.append(Paragraph(f"<b>Source:</b> {safe_text(vuln.get('source'))}", wrap_style))

                    elements.append(Paragraph(f"<b>Type:</b> {safe_text(vuln.get('type'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Description:</b> {safe_text(vuln.get('description'))}", wrap_style))

                    elements.append(Paragraph(f"<b>Title:</b> {safe_text(vuln.get('title'))}", wrap_style))
                    elements.append(Paragraph(f"<b>File:</b> {safe_text(vuln.get('file'))}", wrap_style))
                    elements.append(Paragraph(f"<b>Message:</b> {safe_text(vuln.get('message'))}", wrap_style))
                    elements.append(Spacer(1, 12))
    
    elements.append(Paragraph("Packages", styles["Heading2"]))

    packages = summary_report.get("packages")

    if not packages:
        elements.append(Paragraph(f"<b>No packages found</b>", wrap_style))
    else:
        for package in summary_report.get("packages", []):
            if package:
                elements.append(Paragraph(f"<b>ID:</b> {safe_text(package.get('id'))}", wrap_style))
                elements.append(Paragraph(f"<b>Source:</b> {safe_text(package.get('source'))}", wrap_style))
                elements.append(Paragraph(f"<b>Name:</b> {safe_text(package.get('name'))}", wrap_style))

                elements.append(Paragraph(f"<b>Version:</b> {safe_text(package.get('version'))}", wrap_style))
                elements.append(Paragraph(f"<b>Type:</b> {safe_text(package.get('type'))}", wrap_style))
                elements.append(Paragraph(f"<b>PURL:</b> {safe_text(package.get('purl'))}", wrap_style))
                elements.append(Paragraph(f"<b>CPE:</b> {safe_text(package.get('cpe'))}", wrap_style))

                elements.append(Paragraph(f"<b>Package type:</b> {safe_text(package.get('package_type'))}", wrap_style))
                elements.append(Paragraph(f"<b>Language:</b> {safe_text(package.get('language'))}", wrap_style))
                elements.append(Paragraph(f"<b>Metadata type:</b> {safe_text(package.get('metadata_type'))}", wrap_style))

                elements.append(Paragraph(f"<b>Found by:</b> {safe_text(package.get('found_by'))}", wrap_style))
                elements.append(Paragraph(f"<b>Locations:</b> {safe_text(package.get('locations'))}", wrap_style))
                elements.append(Spacer(1, 12))

    doc.build(elements)
    print(f"[+] PDF report saved as: {pdf_filename_path}")
    return pdf_filename_path