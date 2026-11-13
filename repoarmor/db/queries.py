"""Database query functions."""

from datetime import datetime, timedelta
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from .database import _flush_with_retry
from .models import Repository, Finding, ScanHistory


def _escape_like(value: str) -> str:
    """Escape SQL LIKE wildcard characters to prevent injection.

    Args:
        value: The string to escape.

    Returns:
        String with % and _ escaped with backslash.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# Repository queries

def get_repository_by_url(session: Session, url: str) -> Repository | None:
    """Get a repository by URL."""
    return session.execute(
        select(Repository).where(Repository.url == url)
    ).scalar_one_or_none()


def get_repository_by_id(session: Session, repo_id: int) -> Repository | None:
    """Get a repository by ID."""
    return session.get(Repository, repo_id)


def get_all_repositories(session: Session, repo_type: str | None = None, owner: str | None = None) -> Sequence[Repository]:
    """Get all repositories."""
    query = (
        select(Repository)
        .options(joinedload(Repository.findings))
        .order_by(Repository.last_scanned.desc().nullslast())
    )
    if repo_type is not None:
        query = query.where(Repository.repo_type == repo_type)
    if owner is not None:
        query = query.where(Repository.name.ilike(f"{_escape_like(owner)}/%", escape="\\"))
    return session.execute(query).unique().scalars().all()


def create_repository(session: Session, url: str, name: str, visibility: str = "public", repo_type: str = "unknown") -> Repository:
    """Create a new repository.

    Args:
        session: Database session.
        url: Repository URL.
        name: Repository name (owner/repo format).
        visibility: Repository visibility (public, private, internal).
        repo_type: Source type (personal, org, docker, unknown).
    """
    repo = Repository(url=url, name=name, visibility=visibility, repo_type=repo_type)
    session.add(repo)
    _flush_with_retry(session)
    return repo


def update_repository_stats(session: Session, repo: Repository) -> None:
    """Update repository statistics."""
    repo.total_findings = len(repo.findings)
    repo.last_scanned = datetime.utcnow()


# Finding queries

def get_finding_by_id(session: Session, finding_id: int) -> Finding | None:
    """Get a finding by ID."""
    return session.execute(
        select(Finding)
        .options(joinedload(Finding.repository))
        .where(Finding.id == finding_id)
    ).scalar_one_or_none()


def get_findings(
    session: Session,
    repo_id: int | None = None,
    org: str | None = None,
    detector_type: str | None = None,
    verified_by_trufflehog: bool | None = None,
    repo_type: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> Sequence[Finding]:
    """Get findings with optional filters."""
    query = select(Finding).options(joinedload(Finding.repository))

    if repo_id is not None:
        query = query.where(Finding.repo_id == repo_id)
    if org is not None or repo_type is not None:
        query = query.join(Repository)
        if org is not None:
            query = query.where(
                Repository.name.ilike(f"{_escape_like(org)}/%", escape="\\")
            )
        if repo_type is not None:
            query = query.where(Repository.repo_type == repo_type)
    if detector_type is not None:
        query = query.where(
            Finding.detector_type.ilike(f"%{_escape_like(detector_type)}%", escape="\\")
        )
    if verified_by_trufflehog is not None:
        query = query.where(Finding.verified_by_trufflehog == verified_by_trufflehog)

    query = query.order_by(Finding.created_at.desc())

    if offset:
        query = query.offset(offset)
    if limit:
        query = query.limit(limit)

    return session.execute(query).scalars().all()


def get_findings_by_repo(session: Session, repo_id: int) -> Sequence[Finding]:
    """Get all findings for a repository."""
    return get_findings(session, repo_id=repo_id)


def get_repositories_for_export(
    session: Session,
    org: str | None = None,
    repo_name: str | None = None,
) -> Sequence[Repository]:
    """Get repositories for export with optional filters."""
    query = select(Repository)

    if org is not None:
        query = query.where(
            Repository.name.ilike(f"{_escape_like(org)}/%", escape="\\")
        )
    if repo_name is not None:
        query = query.where(
            Repository.name.ilike(f"%{_escape_like(repo_name)}%", escape="\\")
        )

    return session.execute(query.order_by(Repository.name)).scalars().all()


def get_findings_by_secret_hash(session: Session, repo_id: int, secret_hash: str) -> Finding | None:
    """Check if a finding with this secret hash exists for the repo."""
    return session.execute(
        select(Finding)
        .where(Finding.repo_id == repo_id)
        .where(Finding.secret_hash == secret_hash)
    ).scalar_one_or_none()


def create_finding(session: Session, **kwargs) -> Finding:
    """Create a new finding."""
    finding = Finding(**kwargs)
    session.add(finding)
    _flush_with_retry(session)
    return finding




# Scan history queries

def create_scan_history(session: Session, repo_id: int, scan_config: str | None = None) -> ScanHistory:
    """Create a scan history record."""
    history = ScanHistory(repo_id=repo_id, scan_config=scan_config)
    session.add(history)
    _flush_with_retry(session)
    return history


def complete_scan_history(
    session: Session,
    history: ScanHistory,
    findings_count: int,
    new_findings_count: int,
    status: str = "completed",
    error_message: str | None = None,
) -> ScanHistory:
    """Mark a scan as completed."""
    history.completed_at = datetime.utcnow()
    history.findings_count = findings_count
    history.new_findings_count = new_findings_count
    history.status = status
    history.error_message = error_message
    return history


# Statistics queries

def get_total_findings_count(session: Session) -> int:
    """Get total number of findings."""
    return session.execute(select(func.count(Finding.id))).scalar() or 0


def get_filtered_findings_count(
    session: Session,
    repo_id: int | None = None,
    org: str | None = None,
    detector_type: str | None = None,
    verified_by_trufflehog: bool | None = None,
) -> int:
    """Get count of findings matching filters (same filters as get_findings)."""
    query = select(func.count(Finding.id))

    if repo_id is not None:
        query = query.where(Finding.repo_id == repo_id)
    if org is not None:
        query = query.join(Repository).where(
            Repository.name.ilike(f"{_escape_like(org)}/%", escape="\\")
        )
    if detector_type is not None:
        query = query.where(
            Finding.detector_type.ilike(f"%{_escape_like(detector_type)}%", escape="\\")
        )
    if verified_by_trufflehog is not None:
        query = query.where(Finding.verified_by_trufflehog == verified_by_trufflehog)

    return session.execute(query).scalar() or 0


def get_findings_count_by_type(session: Session) -> dict[str, int]:
    """Get findings count grouped by detector type."""
    results = session.execute(
        select(Finding.detector_type, func.count(Finding.id))
        .group_by(Finding.detector_type)
    ).all()
    return {dtype: count for dtype, count in results}


def get_findings_count_by_org(session: Session, limit: int = 15) -> dict[str, int]:
    """Get findings count grouped by organization.

    Args:
        session: Database session.
        limit: Maximum number of orgs to return (sorted by count desc).

    Returns:
        Dict mapping org name to finding count.
    """
    # Join findings with repositories and group by repo name
    # Then aggregate by org in Python (since org is derived from name)
    results = session.execute(
        select(Repository.name, func.count(Finding.id))
        .join(Finding, Finding.repo_id == Repository.id)
        .group_by(Repository.name)
    ).all()

    # Aggregate by org (extract from "org/repo" format)
    org_counts: dict[str, int] = {}
    for repo_name, count in results:
        org = repo_name.split("/")[0] if "/" in repo_name else repo_name
        org_counts[org] = org_counts.get(org, 0) + count

    # Sort by count descending and limit
    sorted_orgs = sorted(org_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    return dict(sorted_orgs)


def get_findings_count_by_repo(session: Session, limit: int = 20) -> dict[str, int]:
    """Get findings count grouped by repository.

    Args:
        session: Database session.
        limit: Maximum number of repos to return (sorted by count desc).

    Returns:
        Dict mapping repo name to finding count.
    """
    results = session.execute(
        select(Repository.name, func.count(Finding.id))
        .join(Finding, Finding.repo_id == Repository.id)
        .group_by(Repository.name)
        .order_by(func.count(Finding.id).desc())
        .limit(limit)
    ).all()

    return {repo_name: count for repo_name, count in results}


def get_recent_scans_count(session: Session, days: int = 7) -> int:
    """Get count of scans in the last N days."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    return session.execute(
        select(func.count(ScanHistory.id))
        .where(ScanHistory.started_at >= cutoff)
    ).scalar() or 0


def get_total_repos_count(session: Session) -> int:
    """Get total number of repositories."""
    return session.execute(select(func.count(Repository.id))).scalar() or 0
