"""Tests for Docker scan command behavior."""

from sqlalchemy import select

from repoarmor.cli import commands
from repoarmor.config.settings import DatabaseConfig, Settings
from repoarmor.db.database import close_database, session_scope
from repoarmor.db.models import Finding, Repository, ScanHistory
from repoarmor.scanner.trufflehog import ScanResult


def test_scan_docker_updates_repo_stats_and_scan_history(tmp_path, monkeypatch):
    """Docker scans should refresh repo metadata and record scan history."""
    close_database()
    settings = Settings(database=DatabaseConfig(path=tmp_path / "scanner.db"))
    result = ScanResult(
        detector_type="AWS",
        decoder_type=None,
        file_path="/app/config.yml",
        line_number=12,
        commit=None,
        author=None,
        author_email=None,
        commit_date=None,
        message=None,
        secret_hash="abc123",
        redacted_secret="***",
        verified_by_trufflehog=True,
        raw_finding='{"SourceMetadata":{}}',
    )

    monkeypatch.setattr(commands, "get_settings", lambda: settings)
    monkeypatch.setattr(commands, "ensure_trufflehog", lambda: True)
    monkeypatch.setattr(commands, "setup_logging", lambda verbose=False: None)
    monkeypatch.setattr(commands, "scan_docker_image", lambda *args, **kwargs: iter([result]))

    try:
        commands.scan_docker(
            images=["nginx:latest"],
            image_list=None,
            only_verified=False,
            verbose=False,
        )

        with session_scope() as session:
            repo = session.execute(
                select(Repository).where(Repository.url == "nginx:latest")
            ).scalar_one()
            history = session.execute(
                select(ScanHistory).where(ScanHistory.repo_id == repo.id)
            ).scalar_one()
            findings = session.execute(
                select(Finding).where(Finding.repo_id == repo.id)
            ).scalars().all()

            assert repo.repo_type == "docker"
            assert repo.total_findings == 1
            assert repo.last_scanned is not None
            assert len(findings) == 1
            assert history.status == "completed"
            assert history.findings_count == 1
            assert history.new_findings_count == 1
            assert history.completed_at is not None
    finally:
        close_database()
