"""Vulnerability ranking and scoring module."""

from typing import Dict, List, Tuple

# Impact scores by vulnerability class
IMPACT_SCORES = {
    # Critical impact (4)
    "command_injection": 4,
    "deserialization": 4,
    "secrets_exposure": 4,
    # High impact (3)
    "sqli": 3,
    "ssrf": 3,
    "authz": 3,
    "idor": 3,
    # Medium impact (2)
    "xss": 2,
    "path_traversal": 2,
    # Low impact (1)
    "input_validation": 1,
}

# Exposure scores
EXPOSURE_SCORES = {
    "public_facing": 5,
    "local_only": 1,
}

# Exploitability scores
EXPLOITABILITY_SCORES = {
    "easy": 3,
    "moderate": 2,
    "hard": 1,
}


def get_severity_label(score: int) -> str:
    """Get severity label based on score.

    Args:
        score: The vulnerability score (0-10).

    Returns:
        Severity label: Critical, High, Medium, or Low.
    """
    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"


def estimate_exposure(finding: Dict) -> str:
    """Estimate the exposure level of a vulnerability.

    Args:
        finding: The vulnerability finding dict.

    Returns:
        "public_facing" or "local_only"
    """
    # Check for indicators of public-facing exposure
    source = finding.get("source", "").lower()
    sink = finding.get("sink", "").lower()
    description = finding.get("description", "").lower()
    vuln_class = finding.get("class", "").lower()
    url = finding.get("url", "")

    # Frontend findings are always public-facing
    if finding.get("_source") == "frontend":
        return "public_facing"

    # HTTP-related sources are public-facing
    public_indicators = [
        "http",
        "request",
        "api",
        "endpoint",
        "query",
        "parameter",
        "form",
        "user input",
        "upload",
        "web",
        "url",
        "route",
    ]

    for indicator in public_indicators:
        if indicator in source or indicator in description:
            return "public_facing"

    # XSS, IDOR, authz issues are typically public-facing
    if vuln_class in ["xss", "idor", "authz", "sqli", "ssrf"]:
        return "public_facing"

    # If there's a URL, it's public-facing
    if url:
        return "public_facing"

    # Local indicators
    local_indicators = [
        "cli",
        "command line",
        "config",
        "environment",
        "local file",
        "script",
    ]

    for indicator in local_indicators:
        if indicator in source or indicator in description:
            return "local_only"

    # Default to public-facing for security (assume worst case)
    return "public_facing"


def estimate_exploitability(finding: Dict) -> str:
    """Estimate how easy it is to exploit a vulnerability.

    Args:
        finding: The vulnerability finding dict.

    Returns:
        "easy", "moderate", or "hard"
    """
    vuln_class = finding.get("class", "").lower()
    description = finding.get("description", "").lower()
    source = finding.get("source", "").lower()

    # Easy to exploit: direct input, no auth required
    easy_indicators = [
        "no authentication",
        "without auth",
        "unauthenticated",
        "public endpoint",
        "directly controllable",
        "user-supplied",
        "query parameter",
        "form input",
    ]

    for indicator in easy_indicators:
        if indicator in description or indicator in source:
            return "easy"

    # Secrets exposure is easy (just find and use them)
    if vuln_class == "secrets_exposure":
        return "easy"

    # XSS and SQLi with direct input are typically easy
    if vuln_class in ["xss", "sqli"] and any(
        x in source for x in ["input", "parameter", "query", "form"]
    ):
        return "easy"

    # Hard to exploit: requires chaining, special access
    hard_indicators = [
        "chain",
        "multiple steps",
        "admin",
        "privileged",
        "internal",
        "requires access",
    ]

    for indicator in hard_indicators:
        if indicator in description:
            return "hard"

    # IDOR and authz typically require some auth (moderate)
    if vuln_class in ["idor", "authz"]:
        return "moderate"

    # Command injection and deserialization complexity varies
    if vuln_class in ["command_injection", "deserialization"]:
        # If source mentions direct input, it's easier
        if any(x in source for x in ["input", "parameter", "user"]):
            return "moderate"
        return "hard"

    # Default to moderate
    return "moderate"


def calculate_score(finding: Dict) -> Tuple[int, Dict]:
    """Calculate the vulnerability score for a finding.

    Args:
        finding: The vulnerability finding dict.

    Returns:
        A tuple of (score, subscores) where subscores is a dict with
        exposure, exploitability, and impact values.
    """
    vuln_class = finding.get("class", "input_validation").lower()

    # Get impact score (default to 1 for unknown classes)
    impact = IMPACT_SCORES.get(vuln_class, 1)

    # Estimate exposure and exploitability
    exposure_level = estimate_exposure(finding)
    exploitability_level = estimate_exploitability(finding)

    exposure = EXPOSURE_SCORES[exposure_level]
    exploitability = EXPLOITABILITY_SCORES[exploitability_level]

    # Calculate final score (capped at 10)
    score = min(10, exposure + exploitability + impact)

    subscores = {
        "exposure": exposure_level,
        "exposure_score": exposure,
        "exploitability": exploitability_level,
        "exploitability_score": exploitability,
        "impact_score": impact,
    }

    return score, subscores


def rank_findings(findings: List[Dict]) -> List[Dict]:
    """Rank and score all findings.

    Args:
        findings: List of vulnerability findings from scanners.

    Returns:
        List of findings with scores, sorted by score descending.
        Each finding is augmented with: score, severity, and subscores.
    """
    if not findings:
        return []

    # Deduplicate findings by ID
    seen_ids = set()
    unique_findings = []

    for finding in findings:
        finding_id = finding.get("id", "")
        if finding_id and finding_id in seen_ids:
            continue
        if finding_id:
            seen_ids.add(finding_id)
        unique_findings.append(finding)

    # Score each finding
    scored_findings = []
    for finding in unique_findings:
        score, subscores = calculate_score(finding)
        severity = get_severity_label(score)

        # Create a new dict with all the original data plus scores
        scored_finding = {**finding}
        scored_finding["score"] = score
        scored_finding["severity"] = severity
        scored_finding.update(subscores)

        scored_findings.append(scored_finding)

    # Sort by score descending
    scored_findings.sort(key=lambda x: x["score"], reverse=True)

    return scored_findings
