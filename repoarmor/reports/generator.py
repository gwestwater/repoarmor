"""Report generation functionality."""

import csv
import io
import json
from datetime import datetime
from typing import Sequence

from ..db.models import Finding, Repository


def generate_json_report(findings: Sequence[Finding]) -> str:
    """Generate a JSON report from findings.

    Args:
        findings: List of findings to include.

    Returns:
        JSON string.
    """
    report_data = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "summary": _generate_summary(findings),
        "findings": [_finding_to_dict(f) for f in findings],
    }
    return json.dumps(report_data, indent=2)


def generate_csv_report(findings: Sequence[Finding]) -> str:
    """Generate a CSV report from findings.

    Args:
        findings: List of findings to include.

    Returns:
        CSV string.
    """
    output = io.StringIO()

    fieldnames = [
        "id", "repository", "visibility", "detector_type", "file_path", "line_number",
        "commit", "author", "verified_by_trufflehog", "created_at"
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for finding in findings:
        writer.writerow({
            "id": finding.id,
            "repository": finding.repository.name if finding.repository else "",
            "visibility": finding.repository.visibility if finding.repository else "public",
            "detector_type": finding.detector_type,
            "file_path": finding.file_path,
            "line_number": finding.line_number or "",
            "commit": finding.commit or "",
            "author": finding.author or "",
            "verified_by_trufflehog": finding.verified_by_trufflehog,
            "created_at": finding.created_at.isoformat() if finding.created_at else "",
        })

    return output.getvalue()


def generate_markdown_report(findings: Sequence[Finding], title: str = "Secret Scan Report") -> str:
    """Generate a Markdown report from findings.

    Args:
        findings: List of findings to include.
        title: Report title.

    Returns:
        Markdown string.
    """
    lines = [
        f"# {title}",
        "",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Summary",
        "",
    ]

    summary = _generate_summary(findings)
    lines.extend([
        f"- **Total Findings:** {summary['total']}",
        "",
        "### By Detector Type",
        "",
    ])

    for dtype, count in sorted(summary['by_type'].items(), key=lambda x: x[1], reverse=True)[:10]:
        lines.append(f"- {dtype}: {count}")

    lines.extend(["", "## Findings", ""])

    # Group by repository
    by_repo: dict[str, list[Finding]] = {}
    for f in findings:
        repo_name = f.repository.name if f.repository else "Unknown"
        if repo_name not in by_repo:
            by_repo[repo_name] = []
        by_repo[repo_name].append(f)

    for repo_name, repo_findings in by_repo.items():
        visibility = ""
        if repo_findings and repo_findings[0].repository:
            vis = repo_findings[0].repository.visibility.capitalize()
            visibility = f" ({vis})"
        lines.append(f"### {repo_name}{visibility}")
        lines.append("")

        for f in repo_findings:
            verified = "✓ Verified" if f.verified_by_trufflehog else ""
            lines.extend([
                f"#### #{f.id} - {f.detector_type} {verified}",
                "",
                f"- **File:** `{f.file_path}`" + (f":{f.line_number}" if f.line_number else ""),
            ])
            if f.commit:
                lines.append(f"- **Commit:** `{f.commit[:7]}`")
            lines.append("")

    return "\n".join(lines)


def _finding_to_dict(finding: Finding) -> dict:
    """Convert a finding to a dictionary."""
    return {
        "id": finding.id,
        "repository": {
            "id": finding.repository.id if finding.repository else None,
            "name": finding.repository.name if finding.repository else None,
            "url": finding.repository.url if finding.repository else None,
            "visibility": finding.repository.visibility if finding.repository else None,
        },
        "detector_type": finding.detector_type,
        "decoder_type": finding.decoder_type,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "commit": finding.commit,
        "author": finding.author,
        "author_email": finding.author_email,
        "commit_date": finding.commit_date.isoformat() if finding.commit_date else None,
        "verified_by_trufflehog": finding.verified_by_trufflehog,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
    }


def _generate_summary(findings: Sequence[Finding]) -> dict:
    """Generate summary statistics for findings."""
    by_type: dict[str, int] = {}

    for f in findings:
        by_type[f.detector_type] = by_type.get(f.detector_type, 0) + 1

    return {
        "total": len(findings),
        "by_type": by_type,
    }
