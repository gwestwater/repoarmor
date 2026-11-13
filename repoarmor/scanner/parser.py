"""Output parsing and finding deduplication utilities."""

import hashlib
from typing import Sequence

from ..db.models import Finding


def compute_finding_fingerprint(finding: Finding) -> str:
    """Compute a unique fingerprint for a finding.

    This is used for deduplication across scans. A finding is considered
    a duplicate if it has the same:
    - Repository
    - Secret hash
    - File path
    - Detector type

    Args:
        finding: The finding to fingerprint.

    Returns:
        A hex string fingerprint.
    """
    components = [
        str(finding.repo_id),
        finding.secret_hash or "",
        finding.file_path or "",
        finding.detector_type or "",
    ]
    combined = "|".join(components)
    return hashlib.sha256(combined.encode()).hexdigest()


def deduplicate_findings(
    new_findings: Sequence[Finding],
    existing_findings: Sequence[Finding],
) -> list[Finding]:
    """Remove duplicates from new findings based on existing ones.

    Args:
        new_findings: Newly scanned findings.
        existing_findings: Existing findings in database.

    Returns:
        List of findings that are not duplicates.
    """
    # Build set of existing fingerprints
    existing_fingerprints = {
        compute_finding_fingerprint(f) for f in existing_findings
    }

    # Filter out duplicates
    unique_findings = []
    seen_fingerprints = set()

    for finding in new_findings:
        fingerprint = compute_finding_fingerprint(finding)

        if fingerprint in existing_fingerprints:
            continue
        if fingerprint in seen_fingerprints:
            continue

        seen_fingerprints.add(fingerprint)
        unique_findings.append(finding)

    return unique_findings


def group_findings_by_file(findings: Sequence[Finding]) -> dict[str, list[Finding]]:
    """Group findings by file path.

    Args:
        findings: List of findings.

    Returns:
        Dictionary mapping file paths to findings.
    """
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        path = finding.file_path or "unknown"
        if path not in grouped:
            grouped[path] = []
        grouped[path].append(finding)
    return grouped


def group_findings_by_type(findings: Sequence[Finding]) -> dict[str, list[Finding]]:
    """Group findings by detector type.

    Args:
        findings: List of findings.

    Returns:
        Dictionary mapping detector types to findings.
    """
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        detector = finding.detector_type or "unknown"
        if detector not in grouped:
            grouped[detector] = []
        grouped[detector].append(finding)
    return grouped


