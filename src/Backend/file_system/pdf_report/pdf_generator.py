from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, PageBreak, HRFlowable, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from datetime import datetime
from flask import abort
import json
import os
from utils.helpers import safe_text
from external_storage.external_storage_get import get_resources_external_storage_internal_use
from core.variables import all_repo_scans_folder, all_resources_folder
from file_system.pdf_report.pdf_table_builds import *
from file_system.pdf_report.pdf_helpers import build_data_table, normalize_semgrep_ruleset

def summary_to_pdf(organization_decoded, current_repo_decoded, timestamp_decoded):
    grype_exclusions_vulnerabilities_severity_rows = []
    trivy_vulnerability_exclusions_vulnerabilities_severity_rows = []
    semgrep_exclusions_vulnerabilities_severity_rows = []
    trivy_misconfiguration_exclusions_vulnerabilities_severity_rows = []
    trivy_secret_exclusions_vulnerabilities_severity_rows = []
    exclusions_vulnerabilities_severity_rows = []
    kev_vulnerabilities_severity_rows = []
    new_vulnerabilities_severity_rows = []
    vulnerabilities_grype_severity_rows = []
    vulnerabilities_semgrep_severity_rows = []
    vulnerabilities_trivy_severity_rows = []
    misconfigurations_trivy_severity_rows = []
    secrets_trivy_severity_rows = []

    grype_exclusions_vulnerabilities_table_data = fetch_grype_exclusions_vulnerabilities_table_data()
    trivy_vulnerability_exclusions_vulnerabilities_table_data = fetch_trivy_vulnerability_exclusions_vulnerabilities_table_data()
    semgrep_exclusions_vulnerabilities_table_data = fetch_semgrep_exclusions_vulnerabilities_table_data()
    trivy_misconfiguration_exclusions_vulnerabilities_table_data = fetch_trivy_misconfiguration_exclusions_vulnerabilities_table_data()
    trivy_secret_exclusions_vulnerabilities_table_data = fetch_trivy_secret_exclusions_vulnerabilities_table_data()
    exclusions_vulnerabilities_table_data = fetch_exclusions_vulnerabilities_table_data()
    kev_vulnerabilities_table_data = fetch_kev_vulnerabilities_table_data()
    new_vulnerabilities_table_data = fetch_new_vulnerabilities_table_data()
    vulnerabilities_grype_table_data = fetch_vulnerabilities_grype_table_data()
    vulnerabilities_semgrep_table_data = fetch_vulnerabilities_semgrep_table_data()
    vulnerabilities_trivy_table_data = fetch_vulnerabilities_trivy_table_data()
    misconfigurations_trivy_table_data = fetch_misconfigurations_trivy_table_data()
    secrets_trivy_table_data = fetch_secrets_trivy_table_data()
    packages_table_data = fetch_packages_table_data()

    base_dir = os.path.join(all_resources_folder, all_repo_scans_folder, organization_decoded, current_repo_decoded, timestamp_decoded)
    os.makedirs(base_dir, exist_ok=True)
    
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

    table_style = ParagraphStyle(
        name="TableCell",
        fontSize=4,
        leading=8,
        spaceAfter=2,
    )

    doc = SimpleDocTemplate(pdf_filename_path, pagesize=A4)
    elements = []

    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=6, spaceAfter=6))
    elements.append(Paragraph("Security Scan Summary", styles["Title"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=6, spaceAfter=6))
    elements.append(Paragraph(summary_report.get("repo_name"), styles["Title"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=6, spaceAfter=6))
    elements.append(Paragraph(f"<b>Scan date:</b> {scan_generated_date}", wrap_style))
    elements.append(Paragraph(f"<b>Report generated date:</b> {report_generated_date}", wrap_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=6, spaceAfter=12))

    counters = summary_report.get("counters")

    elements.append(Paragraph("Stats", styles["Heading2"]))

    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=6, spaceAfter=6))
    elements.append(Paragraph(f"<b>Packages found:</b> {counters.get('package_counter')}", wrap_style))

    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=6, spaceAfter=6))
    elements.append(Paragraph(f"<b>Excluded vulnerabilities found:</b> {counters.get('excluded_vuln_counter')}", wrap_style))
    elements.append(Paragraph(f"<b>Vulnerabilities found:</b> {counters.get('vuln_counter')}", wrap_style))
    elements.append(Paragraph(f"<b>Excluded KEV vulnerabilities found:</b> {counters.get('excluded_kev_vuln_counter')}", wrap_style))
    elements.append(Paragraph(f"<b>KEV vulnerabilities found:</b> {counters.get('kev_vuln_counter')}", wrap_style))

    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=6, spaceAfter=6))
    elements.append(Paragraph(f"<b>Excluded misconfigurations found:</b> {counters.get('excluded_misconf_counter')}", wrap_style))
    elements.append(Paragraph(f"<b>Misconfigurations found:</b> {counters.get('misconf_counter')}", wrap_style))

    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=6, spaceAfter=6))
    elements.append(Paragraph(f"<b>Excluded exposed secrets found:</b> {counters.get('excluded_exposed_secret_counter')}", wrap_style))
    elements.append(Paragraph(f"<b>Exposed secrets found:</b> {counters.get('exposed_secret_counter')}", wrap_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=6, spaceAfter=12))
    elements.append(Spacer(1, 12))

    tool_version = summary_report.get("tool_version")

    elements.append(Paragraph("Tool versions", styles["Heading2"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=6, spaceAfter=6))
    elements.append(Paragraph(f"<b>Syft:</b> {tool_version.get('syft_version')}", wrap_style))
    elements.append(Paragraph(f"<b>Semgrep:</b> {tool_version.get('semgrep_version')}", wrap_style))
    elements.append(Paragraph(f"<b>Trivy:</b> {tool_version.get('trivy_version')}", wrap_style))
    elements.append(Paragraph(f"<b>Grype:</b> {tool_version.get('grype_version')}", wrap_style))
    elements.append(Paragraph(f"<b>Cosign:</b> {tool_version.get('cosign_version')}", wrap_style))
    elements.append(Paragraph(f"<b>PatchHound:</b> {tool_version.get('patchhound_version')}", wrap_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=6, spaceAfter=12))
    elements.append(Spacer(1, 12))

    rulesets = summary_report.get("ruleset")

    semgrep_rulesets_raw = rulesets.get("semgrep", [])
    semgrep_rulesets = normalize_semgrep_ruleset(semgrep_rulesets_raw)

    if semgrep_rulesets:
        elements.append(Paragraph("Rulesets", styles["Heading2"]))
        elements.append(Paragraph(f"<b>Semgrep ruleset:</b>", wrap_style))
        elements.append(Spacer(1, 6))
        for ruleset in semgrep_rulesets:
            elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=6, spaceAfter=6))
            elements.append(Paragraph(f"<b>{ruleset['name']}</b>", wrap_style))
            elements.append(Paragraph(ruleset["description"], wrap_style))

        elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=6, spaceAfter=12))
        elements.append(Spacer(1, 12))

    exclusions = summary_report.get("exclusions")

    if exclusions:
        for excl in summary_report.get("exclusions", []):
            if excl:
                exclusions_vulnerabilities_severity = safe_text(excl.get("severity"))

                if excl.get("source") == "grype":
                    grype_exclusions_vulnerabilities_row_index = len(grype_exclusions_vulnerabilities_table_data)

                    grype_exclusions_vulnerabilities_table_data.append([
                        Paragraph(safe_text(excl.get("id")), table_style),
                        Paragraph(safe_text(excl.get("source")), table_style),
                        Paragraph(safe_text(excl.get("description")), table_style),

                        Paragraph(exclusions_vulnerabilities_severity, table_style),

                        Paragraph(safe_text(excl.get('type')), table_style),

                        Paragraph(safe_text(excl.get("score")), table_style),
                        Paragraph(safe_text(excl.get("cvss_vector")), table_style),
                        Paragraph(safe_text(excl.get("package")), table_style),
                        Paragraph(safe_text(excl.get("version")), table_style),
                        Paragraph(f"<link href='{safe_text(excl.get('link'))}'>{safe_text(excl.get('link'))}</link>", table_style),

                        Paragraph(safe_text(excl.get('scope')), table_style),
                        Paragraph(safe_text(excl.get('public_comment')), table_style),
                    ])

                    grype_exclusions_vulnerabilities_severity_rows.append((grype_exclusions_vulnerabilities_row_index, exclusions_vulnerabilities_severity))

                elif excl.get("source") == "trivy_vulnerability":
                    trivy_vulnerability_exclusions_vulnerabilities_row_index = len(trivy_vulnerability_exclusions_vulnerabilities_table_data)

                    trivy_vulnerability_exclusions_vulnerabilities_table_data.append([
                        Paragraph(safe_text(excl.get("id")), table_style),
                        Paragraph(safe_text(excl.get("source")), table_style),
                        Paragraph(safe_text(excl.get("description")), table_style),

                        Paragraph(exclusions_vulnerabilities_severity, table_style),

                        Paragraph(safe_text(excl.get('type')), table_style),

                        Paragraph(safe_text(excl.get("score")), table_style),
                        Paragraph(safe_text(excl.get("cvss_vector")), table_style),
                        Paragraph(safe_text(excl.get("package")), table_style),
                        Paragraph(safe_text(excl.get("version")), table_style),
                        Paragraph(f"<link href='{safe_text(excl.get('link'))}'>{safe_text(excl.get('link'))}</link>", table_style),

                        Paragraph(safe_text(excl.get('scope')), table_style),
                        Paragraph(safe_text(excl.get('public_comment')), table_style),
                    ])

                    trivy_vulnerability_exclusions_vulnerabilities_severity_rows.append((trivy_vulnerability_exclusions_vulnerabilities_row_index, exclusions_vulnerabilities_severity))

                elif excl.get("source") == "semgrep":
                    semgrep_exclusions_vulnerabilities_row_index = len(semgrep_exclusions_vulnerabilities_table_data)

                    semgrep_exclusions_vulnerabilities_table_data.append([
                        Paragraph(safe_text(excl.get("id")), table_style),
                        Paragraph(safe_text(excl.get("source")), table_style),
                        Paragraph(safe_text(excl.get("description")), table_style),

                        Paragraph(exclusions_vulnerabilities_severity, table_style),

                        Paragraph(safe_text(excl.get('type')), table_style),

                        Paragraph(safe_text(excl.get("path")), table_style),
                        Paragraph(safe_text(excl.get("line")), table_style),

                        Paragraph(safe_text(excl.get('scope')), table_style),
                        Paragraph(safe_text(excl.get('public_comment')), table_style),
                    ])

                    semgrep_exclusions_vulnerabilities_severity_rows.append((semgrep_exclusions_vulnerabilities_row_index, exclusions_vulnerabilities_severity))

                elif excl.get("source") == "trivy_misconfiguration":
                    trivy_misconfiguration_exclusions_vulnerabilities_row_index = len(trivy_misconfiguration_exclusions_vulnerabilities_table_data)

                    links = excl.get("links", [])
                    misconfig_links = ""

                    if links:
                        misconfig_links = "<br/>".join(
                            f"{i}. <link href='{safe_text(link)}'>{safe_text(link)}</link>"
                            for i, link in enumerate(links, 1)
                        )

                    trivy_misconfiguration_exclusions_vulnerabilities_table_data.append([
                        Paragraph(safe_text(excl.get("id")), table_style),
                        Paragraph(safe_text(excl.get("source")), table_style),
                        Paragraph(safe_text(excl.get("description")), table_style),

                        Paragraph(exclusions_vulnerabilities_severity, table_style),

                        Paragraph(safe_text(excl.get('type')), table_style),

                        Paragraph(safe_text(excl.get("title")), table_style),
                        Paragraph(safe_text(excl.get("resolution")), table_style),
                        Paragraph(safe_text(excl.get("file")), table_style),
                        Paragraph(misconfig_links or "-", table_style),

                        Paragraph(safe_text(excl.get('scope')), table_style),
                        Paragraph(safe_text(excl.get('public_comment')), table_style),
                    ])

                    trivy_misconfiguration_exclusions_vulnerabilities_severity_rows.append((trivy_misconfiguration_exclusions_vulnerabilities_row_index, exclusions_vulnerabilities_severity))

                elif excl.get("source") == "trivy_secret":
                    trivy_secret_exclusions_vulnerabilities_row_index = len(trivy_secret_exclusions_vulnerabilities_table_data)

                    trivy_secret_exclusions_vulnerabilities_table_data.append([
                        Paragraph(safe_text(excl.get("id")), table_style),
                        Paragraph(safe_text(excl.get("source")), table_style),
                        Paragraph(safe_text(excl.get("description")), table_style),

                        Paragraph(exclusions_vulnerabilities_severity, table_style),

                        Paragraph(safe_text(excl.get('type')), table_style),

                        Paragraph(safe_text(vuln.get("title")), table_style),
                        Paragraph(safe_text(vuln.get("file")), table_style),
                        Paragraph(safe_text(vuln.get("message")), table_style),

                        Paragraph(safe_text(excl.get('scope')), table_style),
                        Paragraph(safe_text(excl.get('public_comment')), table_style),
                    ])

                    trivy_secret_exclusions_vulnerabilities_severity_rows.append((trivy_secret_exclusions_vulnerabilities_row_index, exclusions_vulnerabilities_severity))

                else:
                    exclusions_vulnerabilities_row_index = len(exclusions_vulnerabilities_table_data)

                    exclusions_vulnerabilities_table_data.append([
                        Paragraph(safe_text(excl.get("id")), table_style),
                        Paragraph(safe_text(excl.get("source")), table_style),
                        Paragraph(safe_text(excl.get("description")), table_style),

                        Paragraph(exclusions_vulnerabilities_severity, table_style),

                        Paragraph(safe_text(excl.get('type')), table_style),

                        Paragraph(safe_text(excl.get('score')), table_style),
                        Paragraph(safe_text(excl.get('cvss_vector')), table_style),
                        Paragraph(safe_text(excl.get('vuln_source')), table_style),
                        Paragraph(safe_text(excl.get('package')), table_style),
                        Paragraph(safe_text(excl.get('version')), table_style),
                        Paragraph(f"<link href='{excl.get('link')}'>{excl.get('link')}</link>", table_style),
                        
                        Paragraph(safe_text(excl.get('scope')), table_style),
                        Paragraph(safe_text(excl.get('public_comment')), table_style),
                    ])

                    exclusions_vulnerabilities_severity_rows.append((exclusions_vulnerabilities_row_index, exclusions_vulnerabilities_severity))

    kev_vulnerabilities = summary_report.get("kev_vulnerabilities")

    if kev_vulnerabilities:
        for kev_vuln in summary_report.get("kev_vulnerabilities", []):
            if kev_vuln:
                kev_vulnerabilities_row_index = len(kev_vulnerabilities_table_data)

                kev_vulnerabilities_severity = safe_text(kev_vuln.get("severity"))

                kev_vulnerabilities_table_data.append([
                    Paragraph(safe_text(kev_vuln.get("id")), table_style),
                    Paragraph(safe_text(kev_vuln.get("source")), table_style),
                    Paragraph(safe_text(kev_vuln.get("description")), table_style),

                    Paragraph(kev_vulnerabilities_severity, table_style),

                    Paragraph(safe_text(kev_vuln.get("type")), table_style),

                    Paragraph(safe_text(kev_vuln.get("kev_priority")), table_style),
                    Paragraph(safe_text(kev_vuln.get("vendor")), table_style),
                    Paragraph(safe_text(kev_vuln.get("title")), table_style),
                    Paragraph(safe_text(kev_vuln.get("required_action")), table_style),
                    Paragraph(safe_text(kev_vuln.get("kev_added_date")), table_style),
                    Paragraph(safe_text(kev_vuln.get("kev_due_date")), table_style),
                    Paragraph(f"<link href='{kev_vuln.get('link')}'>{kev_vuln.get('link')}</link>", table_style),
                ])

                kev_vulnerabilities_severity_rows.append((kev_vulnerabilities_row_index, kev_vulnerabilities_severity))

    new_vulnerabilities = summary_report.get("new_vulnerabilities")

    if new_vulnerabilities:
        for new_vuln in summary_report.get("new_vulnerabilities", []):
            if new_vuln:
                new_vulnerabilities_row_index = len(new_vulnerabilities_table_data)

                new_vulnerabilities_severity = safe_text(new_vuln.get("severity"))

                new_vulnerabilities_table_data.append([
                    Paragraph(safe_text(new_vuln.get("id")), table_style),
                    Paragraph(safe_text(new_vuln.get("source")), table_style),
                    Paragraph(safe_text(new_vuln.get("description")), table_style),

                    Paragraph(new_vulnerabilities_severity, table_style),

                    Paragraph(safe_text(new_vuln.get("type")), table_style),

                    Paragraph(safe_text(new_vuln.get("score")), table_style),
                    Paragraph(safe_text(new_vuln.get("cvss_vector")), table_style),
                    Paragraph(safe_text(new_vuln.get("vuln_found_timestamp")), table_style),
                    Paragraph(safe_text(new_vuln.get("package")), table_style),
                    Paragraph(safe_text(new_vuln.get("source")), table_style),
                    Paragraph(f"<link href='{safe_text(new_vuln.get('link'))}'>{safe_text(new_vuln.get('link'))}</link>", table_style),
                ])

                new_vulnerabilities_severity_rows.append((new_vulnerabilities_row_index, new_vulnerabilities_severity))

    vulnerabilities = summary_report.get("vulnerabilities")

    if vulnerabilities:
        for vuln in summary_report.get("vulnerabilities", []):
            if vuln:

                if vuln.get('source') == "grype":
                    vulnerabilities_grype_row_index = len(vulnerabilities_grype_table_data)

                    vulnerabilities_grype_severity = safe_text(vuln.get("severity"))

                    vulnerabilities_grype_table_data.append([
                        Paragraph(safe_text(vuln.get("id")), table_style),
                        Paragraph(safe_text(vuln.get("source")), table_style),
                        Paragraph(safe_text(vuln.get("description")), table_style),

                        Paragraph(vulnerabilities_grype_severity, table_style),

                        Paragraph(safe_text(vuln.get("type")), table_style),

                        Paragraph(safe_text(vuln.get("score")), table_style),
                        Paragraph(safe_text(vuln.get("cvss_vector")), table_style),
                        Paragraph(safe_text(vuln.get("package")), table_style),
                        Paragraph(safe_text(vuln.get("version")), table_style),
                        Paragraph(f"<link href='{safe_text(vuln.get('link'))}'>{safe_text(vuln.get('link'))}</link>", table_style),
                    ])

                    vulnerabilities_grype_severity_rows.append((vulnerabilities_grype_row_index, vulnerabilities_grype_severity))

                elif vuln.get('source') == "semgrep":
                    semgrep_row_index = len(vulnerabilities_semgrep_table_data)

                    semgrep_severity = safe_text(vuln.get("severity"))

                    vulnerabilities_semgrep_table_data.append([
                        Paragraph(safe_text(vuln.get("id")), table_style),
                        Paragraph(safe_text(vuln.get("source")), table_style),
                        Paragraph(safe_text(vuln.get("description")), table_style),

                        Paragraph(semgrep_severity, table_style),

                        Paragraph(safe_text(vuln.get("type")), table_style),
                        
                        Paragraph(safe_text(vuln.get("path")), table_style),
                        Paragraph(safe_text(vuln.get("line")), table_style),
                    ])

                    vulnerabilities_semgrep_severity_rows.append((semgrep_row_index, semgrep_severity))
                    
                elif vuln.get('source') == "trivy_vulnerability":
                    vulnerabilities_trivy_row_index = len(vulnerabilities_trivy_table_data)

                    vulnerabilities_trivy_severity = safe_text(vuln.get("severity"))

                    vulnerabilities_trivy_table_data.append([
                        Paragraph(safe_text(vuln.get("id")), table_style),
                        Paragraph(safe_text(vuln.get("source")), table_style),
                        Paragraph(safe_text(vuln.get("description")), table_style),

                        Paragraph(vulnerabilities_trivy_severity, table_style),

                        Paragraph(safe_text(vuln.get("type")), table_style),

                        Paragraph(safe_text(vuln.get("score")), table_style),
                        Paragraph(safe_text(vuln.get("cvss_vector")), table_style),
                        Paragraph(safe_text(vuln.get("package")), table_style),
                        Paragraph(safe_text(vuln.get("version")), table_style),
                        Paragraph(f"<link href='{safe_text(vuln.get('link'))}'>{safe_text(vuln.get('link'))}</link>", table_style),
                    ])

                    vulnerabilities_trivy_severity_rows.append((vulnerabilities_trivy_row_index, vulnerabilities_trivy_severity))

                elif vuln.get('source') == "trivy_misconfiguration":
                    misconfigurations_trivy_row_index = len(misconfigurations_trivy_table_data)

                    misconfigurations_trivy_severity = safe_text(vuln.get("severity"))

                    links = vuln.get("links", [])
                    misconfig_links = ""

                    if links:
                        misconfig_links = "<br/>".join(
                            f"{i}. <link href='{safe_text(link)}'>{safe_text(link)}</link>"
                            for i, link in enumerate(links, 1)
                        )

                    misconfigurations_trivy_table_data.append([
                        Paragraph(safe_text(vuln.get("id")), table_style),
                        Paragraph(safe_text(vuln.get("source")), table_style),
                        Paragraph(safe_text(vuln.get("description")), table_style),

                        Paragraph(misconfigurations_trivy_severity, table_style),

                        Paragraph(safe_text(vuln.get("type")), table_style),

                        Paragraph(safe_text(vuln.get("title")), table_style),
                        Paragraph(safe_text(vuln.get("resolution")), table_style),
                        Paragraph(safe_text(vuln.get("file")), table_style),
                        Paragraph(misconfig_links or "-", table_style),
                    ])

                    misconfigurations_trivy_severity_rows.append((misconfigurations_trivy_row_index, misconfigurations_trivy_severity))

                elif vuln.get('source') == "trivy_secret":
                    secrets_trivy_row_index = len(secrets_trivy_table_data)

                    secrets_trivy_severity = safe_text(vuln.get("severity"))

                    secrets_trivy_table_data.append([
                        Paragraph(safe_text(vuln.get("id")), table_style),
                        Paragraph(safe_text(vuln.get("source")), table_style),
                        Paragraph(safe_text(vuln.get("description")), table_style),

                        Paragraph(secrets_trivy_severity, table_style),

                        Paragraph(safe_text(vuln.get("type")), table_style),

                        Paragraph(safe_text(vuln.get("title")), table_style),
                        Paragraph(safe_text(vuln.get("file")), table_style),
                        Paragraph(safe_text(vuln.get("message")), table_style),
                    ])

                    secrets_trivy_severity_rows.append((secrets_trivy_row_index, secrets_trivy_severity))

    packages = summary_report.get("packages")

    if packages:
        for package in summary_report.get("packages", []):
            if package:
                packages_table_data.append([
                    Paragraph(safe_text(package.get("id")), table_style),
                    Paragraph(safe_text(package.get("source")), table_style),
                    
                    Paragraph(safe_text(package.get("name")), table_style),
                    Paragraph(safe_text(package.get("version")), table_style),
                    Paragraph(safe_text(package.get("type")), table_style),
                    Paragraph(safe_text(package.get("purl")), table_style),
                    Paragraph(safe_text(package.get("cpe")), table_style),
                    Paragraph(safe_text(package.get("package_type")), table_style),
                    Paragraph(safe_text(package.get("language")), table_style),
                    Paragraph(safe_text(package.get("metadata_type")), table_style),
                    Paragraph(safe_text(package.get("found_by")), table_style),
                    Paragraph(safe_text(package.get("locations")), table_style),
                ])
                
    grype_exclusions_vulnerabilities_table = build_data_table(grype_exclusions_vulnerabilities_table_data, grype_exclusions_vulnerabilities_severity_rows, grype_excl_col_widths)
    trivy_vulnerability_exclusions_vulnerabilities_table = build_data_table(trivy_vulnerability_exclusions_vulnerabilities_table_data, trivy_vulnerability_exclusions_vulnerabilities_severity_rows, trivy_vulnerability_excl_col_widths)
    semgrep_exclusions_vulnerabilities_table = build_data_table(semgrep_exclusions_vulnerabilities_table_data, semgrep_exclusions_vulnerabilities_severity_rows, semgrep_excl_col_widths)
    trivy_misconfiguration_exclusions_vulnerabilities_table = build_data_table(trivy_misconfiguration_exclusions_vulnerabilities_table_data, trivy_misconfiguration_exclusions_vulnerabilities_severity_rows, trivy_misconfiguration_excl_col_widths)
    trivy_secret_exclusions_vulnerabilities_table = build_data_table(trivy_secret_exclusions_vulnerabilities_table_data, trivy_secret_exclusions_vulnerabilities_severity_rows, trivy_secret_excl_col_widths)
    exclusions_vulnerabilities_table = build_data_table(exclusions_vulnerabilities_table_data, exclusions_vulnerabilities_severity_rows, excl_col_widths)

    kev_vulnerabilities_table = build_data_table(kev_vulnerabilities_table_data, kev_vulnerabilities_severity_rows, kev_col_widths)
    new_vulnerabilities_table = build_data_table(new_vulnerabilities_table_data, new_vulnerabilities_severity_rows, new_vuln_col_widths)
    vulnerabilities_grype_table = build_data_table(vulnerabilities_grype_table_data, vulnerabilities_grype_severity_rows, grype_vuln_col_widths)
    vulnerabilities_semgrep_table = build_data_table(vulnerabilities_semgrep_table_data, vulnerabilities_semgrep_severity_rows, semgrep_col_widths)
    vulnerabilities_trivy_table = build_data_table(vulnerabilities_trivy_table_data, vulnerabilities_trivy_severity_rows, trivy_vuln_col_widths)
    misconfigurations_trivy_table = build_data_table(misconfigurations_trivy_table_data, misconfigurations_trivy_severity_rows, trivy_misconfig_col_widths)
    secrets_trivy_table = build_data_table(secrets_trivy_table_data, secrets_trivy_severity_rows, trivy_secrets_col_widths)
    packages_table = build_data_table(packages_table_data, None, packages_col_widths)

    if not exclusions:
        elements.append(Paragraph("<b>No exclusions found</b>", wrap_style))
    else:
        elements.append(PageBreak())
        elements.append(Paragraph("Exclusions", styles["Heading2"]))
        if grype_exclusions_vulnerabilities_table or trivy_vulnerability_exclusions_vulnerabilities_table or semgrep_exclusions_vulnerabilities_table:
            elements.append(Paragraph(f"<b>Vulnerabilities</b>", wrap_style))

            if grype_exclusions_vulnerabilities_table:
                elements.append(grype_exclusions_vulnerabilities_table)
                elements.append(Spacer(1, 12))

            if trivy_vulnerability_exclusions_vulnerabilities_table:
                elements.append(trivy_vulnerability_exclusions_vulnerabilities_table)
                elements.append(Spacer(1, 12))

            if semgrep_exclusions_vulnerabilities_table:
                elements.append(semgrep_exclusions_vulnerabilities_table)
                elements.append(Spacer(1, 12))

        if trivy_misconfiguration_exclusions_vulnerabilities_table:
            elements.append(Paragraph(f"<b>Misconfigurations</b>", wrap_style))
            elements.append(trivy_misconfiguration_exclusions_vulnerabilities_table)
            elements.append(Spacer(1, 12))

        if trivy_secret_exclusions_vulnerabilities_table:
            elements.append(Paragraph(f"<b>Exposed secrets</b>", wrap_style))
            elements.append(trivy_secret_exclusions_vulnerabilities_table)
            elements.append(Spacer(1, 12))

        if exclusions_vulnerabilities_table:
            elements.append(exclusions_vulnerabilities_table)
            elements.append(Spacer(1, 12))

    if not kev_vulnerabilities:
        elements.append(Paragraph(f"<b>No vulnerabilities found in CISA KEV</b>", wrap_style))
    else:
        elements.append(PageBreak())
        elements.append(Paragraph("<b>CISA KEV Prioritized Vulnerabilities</b>", styles["Heading2"]))
        elements.append(kev_vulnerabilities_table)
        elements.append(Spacer(1, 12))

    if new_vulnerabilities:
        elements.append(PageBreak())
        elements.append(Paragraph("<b>New Found Vulnerabilities</b>", styles["Heading2"]))
        elements.append(new_vulnerabilities_table)
        elements.append(Spacer(1, 12))

    if not vulnerabilities:
        elements.append(Paragraph(f"<b>No vulnerabilities found</b>", wrap_style))
    else:
        elements.append(PageBreak())
        elements.append(Paragraph("<b>Vulnerabilities</b>", styles["Heading2"]))
        elements.append(vulnerabilities_grype_table)
        elements.append(Spacer(1, 12))
        elements.append(vulnerabilities_trivy_table)
        elements.append(Spacer(1, 12))
        elements.append(vulnerabilities_semgrep_table)
        elements.append(Spacer(1, 12))

        if misconfigurations_trivy_table:
            elements.append(PageBreak())
            elements.append(Paragraph("<b>Misconfigurations</b>", styles["Heading2"]))
            elements.append(misconfigurations_trivy_table)
            elements.append(Spacer(1, 12))

        if secrets_trivy_table:
            elements.append(PageBreak())
            elements.append(Paragraph("<b>Exposed Secrets</b>", styles["Heading2"]))
            elements.append(secrets_trivy_table)
            elements.append(Spacer(1, 12))

    if not packages:
        elements.append(Paragraph(f"<b>No packages found</b>", wrap_style))
    else:
        elements.append(PageBreak())
        elements.append(Paragraph("<b>Packages</b>", styles["Heading2"]))
        elements.append(packages_table)
        elements.append(Spacer(1, 12))

    doc.build(elements)
    print(f"[+] PDF report saved as: {pdf_filename_path}")
    return pdf_filename_path