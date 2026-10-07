from ast_sentinel.schemas.findings import ScanResult, Severity

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def compute_risk_score(result: ScanResult, avg_complexity: float = 0.0) -> float:
    """
    Composite Code Risk Score:
        Risk = Σ(severity_weight × finding_count) + complexity_penalty
    Normalized to 0-100 scale.
    """
    weighted_sum = 0.0
    for fa in result.files_analyzed:
        for finding in fa.findings:
            weighted_sum += SEVERITY_WEIGHTS.get(finding.severity, 0)

    complexity_penalty = max(0.0, avg_complexity - 10) * 0.5
    raw_score = weighted_sum + complexity_penalty

    # Normalize: cap at 100
    normalized = min(100.0, raw_score)
    return round(normalized, 1)


def risk_grade(score: float) -> str:
    if score <= 10:
        return "A"
    elif score <= 25:
        return "B"
    elif score <= 50:
        return "C"
    elif score <= 75:
        return "D"
    else:
        return "F"
