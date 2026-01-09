def check_alert_status(alert_on_severity, grype_critical_count, grype_high_count, grype_medium_count, grype_low_count, grype_unknown_count, trivy_crit_count, trivy_high_count, trivy_medium_count, trivy_low_count, trivy_unknown_count):
    if alert_on_severity == "critical":
        if grype_critical_count + trivy_crit_count > 0:
            return True

    elif alert_on_severity == "high":
        if grype_high_count + trivy_high_count > 0:
            return True

    elif alert_on_severity == "medium":
        if grype_medium_count + trivy_medium_count > 0:
            return True

    elif alert_on_severity == "low":
        if grype_low_count + trivy_low_count > 0:
            return True
    
    elif alert_on_severity == "unknown":
        if grype_unknown_count + trivy_unknown_count > 0:
            return True
    
    else:
        return False