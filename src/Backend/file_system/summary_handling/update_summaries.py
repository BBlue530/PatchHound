import os
import json
import shutil
from file_system.summary_handling.summary_generator import generate_summary
from file_system.repo_history_tracking import update_repo_history_rescan
from external_storage.external_storage_get import get_resources_external_storage_internal_use_tmp
from external_storage.external_storage_send import send_files_to_external_storage
from utils.helpers import load_file_data
from core.variables import *

def update_repo_summaries(audit_trail, repo_dir, repo_name):
    temp_resources_root = None
    try:
        if os.environ.get("external_storage_enabled", "False").lower() == "true":
            temp_resources_root = get_resources_external_storage_internal_use_tmp(repo_dir)

            repo_scans_dir = temp_resources_root

            print(repo_scans_dir)

            if not os.path.isdir(repo_scans_dir):
                print(f"[!] AWS s3 missing repo file: {temp_resources_root}")
                return
        else:
            repo_scans_dir = repo_dir

        repo_exclusion_file_name = f"{repo_name}{exclusions_file_path_ending}"
        repo_exclusions_file_path = os.path.join(repo_scans_dir, repo_exclusion_file_name)

        repo_alert_file_name = f"{repo_name}{alert_path_ending}"
        repo_alert__file_path = os.path.join(repo_scans_dir, repo_alert_file_name)

        repo_history_file_name = f"{repo_name}{repo_history_path_ending}"
        repo_history_file_path = os.path.join(repo_scans_dir, repo_history_file_name)

        for timestamp_scan_data in os.listdir(repo_scans_dir):
            timestamp_scan_data_dir = os.path.join(repo_scans_dir, timestamp_scan_data) 
            if not os.path.isdir(timestamp_scan_data_dir):
                continue

            syft_sbom_path = os.path.join(timestamp_scan_data_dir, f"{repo_name}{syft_sbom_path_ending}")
            grype_path = os.path.join(timestamp_scan_data_dir, f"{repo_name}{grype_path_ending}")
            prio_path = os.path.join(timestamp_scan_data_dir, f"{repo_name}{prio_path_ending}")
            semgrep_sast_report_path = os.path.join(timestamp_scan_data_dir, f"{repo_name}{semgrep_sast_report_path_ending}")
            trivy_report_path = os.path.join(timestamp_scan_data_dir, f"{repo_name}{trivy_report_path_ending}")
            summary_report_path = os.path.join(timestamp_scan_data_dir, f"{repo_name}{summary_report_path_ending}")

            tool_versions, rulesets, tmp_dict_summary_data = summary_data(summary_report_path)

            generate_summary(audit_trail, repo_name, syft_sbom_path, grype_path, prio_path, semgrep_sast_report_path, trivy_report_path, repo_exclusions_file_path, summary_report_path, tool_versions, rulesets, tmp_dict_summary_data)
            update_repo_history_rescan(audit_trail, repo_name, repo_alert__file_path, summary_report_path, repo_history_file_path, timestamp_scan_data)

            if os.environ.get("external_storage_enabled", "False").lower() == "true":
                s3_timestamp_dir = os.path.join(repo_dir, timestamp_scan_data)
                send_files_to_external_storage(summary_report_path, s3_timestamp_dir)
                send_files_to_external_storage(repo_history_file_path, repo_dir)

    finally:
        if temp_resources_root:
            shutil.rmtree(temp_resources_root, ignore_errors=True)

def summary_data(summary_report_path):
    summary_report_data = load_file_data(summary_report_path)
    
    tool_versions = summary_report_data.get("tool_version")
    rulesets = summary_report_data.get("ruleset")

    new_vulnerabilities = summary_report_data.get("new_vulnerabilities", [])
    new_excluded_vulnerabilities = summary_report_data.get("new_excluded_vulnerabilities", [])

    new_kev_vulnerabilities = summary_report_data.get("new_kev_vulnerabilities", [])
    new_excluded_kev_vulnerabilities = summary_report_data.get("new_excluded_kev_vulnerabilities", [])

    rescan_timestamp = summary_report_data.get("rescan_timestamp", None)

    counters = summary_report_data.get("counters", {})

    new_vulnerabilities_counter = counters.get("new_vulnerabilities_counter", 0)
    new_excluded_vulnerabilities_counter = counters.get("new_excluded_vulnerabilities_counter", 0)

    new_kev_vulnerabilities_counter = counters.get("new_kev_vulnerabilities_counter", 0)
    new_excluded_kev_vulnerabilities_counter = counters.get("new_excluded_kev_vulnerabilities_counter", 0)

    tmp_dict_summary_data = {
        "new_vulnerabilities": new_vulnerabilities,
        "new_excluded_vulnerabilities": new_excluded_vulnerabilities,

        "new_kev_vulnerabilities": new_kev_vulnerabilities,
        "new_excluded_kev_vulnerabilities": new_excluded_kev_vulnerabilities,

        "rescan_timestamp": rescan_timestamp,

        "new_vulnerabilities_counter": new_vulnerabilities_counter,
        "new_excluded_vulnerabilities_counter": new_excluded_vulnerabilities_counter,

        "new_kev_vulnerabilities_counter": new_kev_vulnerabilities_counter,
        "new_excluded_kev_vulnerabilities_counter": new_excluded_kev_vulnerabilities_counter,
    }

    return tool_versions, rulesets, tmp_dict_summary_data