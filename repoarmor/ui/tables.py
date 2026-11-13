"""Rich table renderers for displaying data."""

from datetime import datetime
from typing import Sequence

from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from ..db.models import Repository, Finding
from ..scanner.pipeline_check import PipelineCheckResult, WorkflowSearchResult
from ..scanner.member_identity import MemberIdentity
from .console import console


def render_member_check_table(results: Sequence[MemberIdentity], title: str = "Member Identity Check") -> None:
    """Render a table showing which GitHub members/collaborators are internal vs. external."""
    if not results:
        console.print("[muted]No members found.[/muted]")
        return

    status_colors = {
        "internal": "[green]Internal[/green]",
        "external": "[red]External[/red]",
        "unknown": "[yellow]Unknown[/yellow]",
    }
    external_count = sum(1 for r in results if r.status == "external")

    table = Table(title=f"{title} ({external_count}/{len(results)} external)", show_lines=True, expand=True)
    table.add_column("Username", style="repo", ratio=1)
    table.add_column("Email", style="muted", overflow="fold", ratio=2)
    table.add_column("Source", justify="center", width=10)
    table.add_column("Status", justify="center", width=10)

    for result in sorted(results, key=lambda r: (r.status != "external", r.username.lower())):
        table.add_row(
            result.username,
            result.email or "-",
            result.source,
            status_colors.get(result.status, result.status),
        )

    console.print(table)


def render_workflow_search_table(
    results: Sequence[WorkflowSearchResult], pattern: str, title: str | None = None
) -> None:
    """Render a table showing which repos' workflows contain a given search pattern."""
    if not results:
        console.print("[muted]No repositories found.[/muted]")
        return

    found_count = sum(1 for r in results if r.found)
    visibility_colors = {"private": "[red]Private[/red]", "internal": "[yellow]Internal[/yellow]", "public": "[green]Public[/green]"}
    title = title or Text.assemble("Workflow Search: '", pattern, "'")
    show_branch = len({r.branch for r in results}) > 1

    table = Table(title=f"{title} ({found_count}/{len(results)} matched)", show_lines=True, expand=True)
    table.add_column("Repository", style="repo", overflow="fold", ratio=2)
    if show_branch:
        table.add_column("Branch", style="muted", overflow="fold", width=16)
    table.add_column("Type", justify="center", width=10)
    table.add_column("Found", justify="center", width=10)
    table.add_column("Workflows", justify="right", width=10)
    table.add_column("Matched File(s)", style="muted", overflow="fold", ratio=2)

    for result in sorted(results, key=lambda r: (r.found, r.repo_full_name.lower(), r.branch)):
        if result.error:
            status = "[yellow]Error[/yellow]"
            detail = result.error
        elif result.found:
            status = "[green]Yes[/green]"
            detail = ", ".join(result.matched_files)
        else:
            status = "[red]No[/red]"
            detail = "-"

        visibility = visibility_colors.get(result.visibility, result.visibility)

        row = [result.repo_full_name]
        if show_branch:
            row.append(result.branch or "-")
        row.extend([visibility, status, str(result.workflow_count), detail])
        table.add_row(*row)

    console.print(table)


def render_pipeline_check_table(results: Sequence[PipelineCheckResult], title: str = "TruffleHog Pipeline Coverage") -> None:
    """Render a table showing which repos have TruffleHog wired into their CI pipeline on PRs."""
    if not results:
        console.print("[muted]No repositories found.[/muted]")
        return

    pr_gated_count = sum(1 for r in results if r.pr_gated)
    visibility_colors = {"private": "[red]Private[/red]", "internal": "[yellow]Internal[/yellow]", "public": "[green]Public[/green]"}
    show_branch = len({r.branch for r in results}) > 1

    table = Table(title=f"{title} ({pr_gated_count}/{len(results)} enabled on PRs)", show_lines=True, expand=True)
    table.add_column("Repository", style="repo", overflow="fold", ratio=2)
    if show_branch:
        table.add_column("Branch", style="muted", overflow="fold", width=16)
    table.add_column("Type", justify="center", width=10)
    table.add_column("TruffleHog", justify="center", width=14)
    table.add_column("Workflows", justify="right", width=10)
    table.add_column("Matched File", style="muted", overflow="fold", ratio=2)

    for result in sorted(results, key=lambda r: (r.pr_gated, r.repo_full_name.lower(), r.branch)):
        if result.error:
            status = "[yellow]Error[/yellow]"
            detail = result.error
        elif result.pr_gated:
            status = "[green]Enabled (Org Rule)[/green]" if result.org_ruleset_enforced else "[green]Enabled (PR)[/green]"
            detail = ", ".join(result.pr_gated_files)
        elif result.has_trufflehog:
            status = "[yellow]Not on PRs[/yellow]"
            detail = ", ".join(result.matched_files)
        else:
            status = "[red]Missing[/red]"
            detail = "-"

        visibility = visibility_colors.get(result.visibility, result.visibility)

        row = [result.repo_full_name]
        if show_branch:
            row.append(result.branch or "-")
        row.extend([visibility, status, str(result.workflow_count), detail])
        table.add_row(*row)

    console.print(table)


def render_repositories_table(repositories: Sequence[Repository], with_stats: bool = False) -> None:
    """Render a table of repositories."""
    if not repositories:
        console.print("[muted]No repositories found.[/muted]")
        return

    table = Table(title="Scanned Repositories", show_lines=True)

    table.add_column("ID", style="dim", width=6)
    table.add_column("Repository", style="repo")
    table.add_column("Type", width=8)
    table.add_column("URL", style="muted", overflow="fold")
    table.add_column("Last Scanned", style="info")

    if with_stats:
        table.add_column("Findings", justify="right")

    for repo in repositories:
        last_scanned = (
            repo.last_scanned.strftime("%Y-%m-%d %H:%M")
            if repo.last_scanned
            else "Never"
        )
        visibility_colors = {"private": "[red]Private[/red]", "internal": "[yellow]Internal[/yellow]", "public": "[green]Public[/green]"}
        visibility = visibility_colors.get(repo.visibility, repo.visibility)

        row = [
            str(repo.id),
            repo.name,
            visibility,
            repo.url,
            last_scanned,
        ]

        if with_stats:
            row.append(str(repo.total_findings))

        table.add_row(*row)

    console.print(table)


def render_findings_table(
    findings: Sequence[Finding],
    show_repo: bool = True,
    compact: bool = False
) -> None:
    """Render a table of findings."""
    if not findings:
        console.print("[muted]No findings found.[/muted]")
        return

    table = Table(title=f"Findings ({len(findings)} total)", show_lines=not compact)

    table.add_column("ID", style="dim", width=6)
    if show_repo:
        table.add_column("Org", style="cyan", max_width=15)
        table.add_column("Repo", style="repo", max_width=20)
        table.add_column("Type", width=8)
    table.add_column("Detector", style="finding.type")
    table.add_column("Secret", style="dim", max_width=20, overflow="fold")
    table.add_column("File", style="finding.file", overflow="fold")
    table.add_column("Verified", justify="center", width=8)
    table.add_column("Commit", style="finding.commit", width=8)

    for finding in findings:
        file_info = finding.file_path
        if finding.line_number:
            file_info = f"{finding.file_path}:{finding.line_number}"

        row = [str(finding.id)]

        if show_repo:
            if finding.repository:
                row.append(finding.repository.org)
                row.append(finding.repository.repo_name)
                visibility_colors = {"private": "[red]Private[/red]", "internal": "[yellow]Internal[/yellow]", "public": "[green]Public[/green]"}
                visibility = visibility_colors.get(finding.repository.visibility, finding.repository.visibility)
                row.append(visibility)
            else:
                row.append("Unknown")
                row.append("Unknown")
                row.append("-")

        row.extend([
            finding.detector_type,
            finding.redacted_secret or "-",
            file_info,
            "[green]✓[/green]" if finding.verified_by_trufflehog else "[dim]-[/dim]",
            finding.commit[:7] if finding.commit else "-",
        ])

        table.add_row(*row)

    console.print(table)


def render_finding_detail(finding: Finding) -> None:
    """Render detailed view of a single finding."""
    # Build the content
    lines = []

    lines.append(f"[header]Finding #{finding.id}[/header]")
    lines.append("")

    # Basic info
    repo_info = finding.repository.name if finding.repository else 'Unknown'
    if finding.repository:
        visibility_colors = {"private": "[red]Private[/red]", "internal": "[yellow]Internal[/yellow]", "public": "[green]Public[/green]"}
        visibility = visibility_colors.get(finding.repository.visibility, finding.repository.visibility)
        repo_info = f"{repo_info} ({visibility})"
    lines.append(f"[highlight]Repository:[/highlight] {repo_info}")
    lines.append(f"[highlight]Detector:[/highlight] [finding.type]{finding.detector_type}[/finding.type]")
    if finding.decoder_type:
        lines.append(f"[highlight]Decoder:[/highlight] {finding.decoder_type}")
    lines.append("")

    # File info
    lines.append("[header]Location[/header]")
    lines.append(f"[highlight]File:[/highlight] [finding.file]{finding.file_path}[/finding.file]")
    if finding.line_number:
        lines.append(f"[highlight]Line:[/highlight] {finding.line_number}")
    lines.append("")

    # Commit info
    if finding.commit:
        lines.append("[header]Commit Information[/header]")
        lines.append(f"[highlight]Commit:[/highlight] [finding.commit]{finding.commit}[/finding.commit]")
        if finding.author:
            author = finding.author
            if finding.author_email:
                author += f" <{finding.author_email}>"
            lines.append(f"[highlight]Author:[/highlight] {author}")
        if finding.commit_date:
            lines.append(f"[highlight]Date:[/highlight] {finding.commit_date.strftime('%Y-%m-%d %H:%M')}")
        if finding.message:
            lines.append(f"[highlight]Message:[/highlight] {finding.message[:100]}...")
        lines.append("")

    # Redacted secret preview
    if finding.redacted_secret:
        lines.append("[header]Secret Preview[/header]")
        lines.append(f"[muted]{finding.redacted_secret}[/muted]")
        lines.append("")

    # Timestamps
    lines.append("[header]Timestamps[/header]")
    lines.append(f"[highlight]Found:[/highlight] {finding.created_at.strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"[highlight]Updated:[/highlight] {finding.updated_at.strftime('%Y-%m-%d %H:%M')}")

    # TruffleHog verification
    if finding.verified_by_trufflehog:
        lines.append("")
        lines.append("[success]✓ Verified by TruffleHog (secret confirmed active)[/success]")

    content = "\n".join(lines)
    panel = Panel(content, title="Finding Details", border_style="cyan")
    console.print(panel)


def render_stats_dashboard(
    total_repos: int,
    total_findings: int,
    findings_by_type: dict[str, int],
    recent_scans: int,
    findings_by_org: dict[str, int] | None = None,
    findings_by_repo: dict[str, int] | None = None,
) -> None:
    """Render a statistics dashboard."""
    from rich.columns import Columns

    console.print()
    console.print("[header]RepoArmor Dashboard[/header]")
    console.print()

    # Summary stats
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    summary_table.add_column("Label", style="muted")
    summary_table.add_column("Value", style="highlight")

    summary_table.add_row("Total Repositories", str(total_repos))
    summary_table.add_row("Total Findings", str(total_findings))
    summary_table.add_row("Recent Scans (7 days)", str(recent_scans))

    console.print(Panel(summary_table, title="Summary", border_style="blue"))
    console.print()

    # Organization and Repository breakdown
    if findings_by_org or findings_by_repo:
        org_table = Table(title="Findings by Organization")
        org_table.add_column("Organization", style="cyan")
        org_table.add_column("Count", justify="right")
        org_table.add_column("Percentage", justify="right")

        if findings_by_org:
            for org_name, count in findings_by_org.items():
                pct = (count / total_findings * 100) if total_findings > 0 else 0
                org_table.add_row(org_name, str(count), f"{pct:.1f}%")
        else:
            org_table.add_row("[muted]No data[/muted]", "-", "-")

        repo_table = Table(title="Findings by Repository")
        repo_table.add_column("Repository", style="repo")
        repo_table.add_column("Count", justify="right")
        repo_table.add_column("Percentage", justify="right")

        if findings_by_repo:
            for repo_name, count in findings_by_repo.items():
                pct = (count / total_findings * 100) if total_findings > 0 else 0
                repo_table.add_row(repo_name, str(count), f"{pct:.1f}%")
        else:
            repo_table.add_row("[muted]No data[/muted]", "-", "-")

        console.print(Columns([org_table, repo_table], equal=True))
        console.print()

    # Top finding types
    if findings_by_type:
        type_table = Table(title="Top Finding Types")
        type_table.add_column("Detector Type", style="finding.type")
        type_table.add_column("Count", justify="right")

        sorted_types = sorted(findings_by_type.items(), key=lambda x: x[1], reverse=True)[:10]
        for detector_type, count in sorted_types:
            type_table.add_row(detector_type, str(count))

        console.print(type_table)
