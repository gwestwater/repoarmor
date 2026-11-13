"""Tests for database models."""

import pytest
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from repoarmor.db.models import Base, Repository, Finding, ScanHistory


@pytest.fixture
def engine():
    """Create an in-memory database engine."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def session(engine):
    """Create a database session."""
    with Session(engine) as session:
        yield session


class TestRepository:
    """Tests for Repository model."""

    def test_create_repository(self, session):
        """Test creating a repository."""
        repo = Repository(
            url="https://github.com/owner/repo",
            name="owner/repo",
        )
        session.add(repo)
        session.commit()

        assert repo.id is not None
        assert repo.url == "https://github.com/owner/repo"
        assert repo.name == "owner/repo"
        assert repo.total_findings == 0
        assert repo.created_at is not None

    def test_repository_unique_url(self, session):
        """Test that repository URLs must be unique."""
        repo1 = Repository(url="https://github.com/owner/repo", name="owner/repo")
        repo2 = Repository(url="https://github.com/owner/repo", name="owner/repo")

        session.add(repo1)
        session.commit()

        session.add(repo2)
        with pytest.raises(Exception):  # IntegrityError
            session.commit()


class TestFinding:
    """Tests for Finding model."""

    def test_create_finding(self, session):
        """Test creating a finding."""
        repo = Repository(url="https://github.com/owner/repo", name="owner/repo")
        session.add(repo)
        session.commit()

        finding = Finding(
            repo_id=repo.id,
            detector_type="AWS",
            file_path="config/secrets.yml",
            secret_hash="abc123",
        )
        session.add(finding)
        session.commit()

        assert finding.id is not None
        assert finding.verified_by_trufflehog is False
        assert finding.repository == repo

    def test_finding_status_default(self, session):
        """Test that finding status defaults to unverified."""
        repo = Repository(url="https://github.com/owner/repo", name="owner/repo")
        session.add(repo)
        session.commit()

        finding = Finding(
            repo_id=repo.id,
            detector_type="AWS",
            file_path="test.py",
            secret_hash="xyz789",
        )
        session.add(finding)
        session.commit()

        assert finding.verified_by_trufflehog is False


class TestScanHistory:
    """Tests for ScanHistory model."""

    def test_create_scan_history(self, session):
        """Test creating scan history."""
        repo = Repository(url="https://github.com/owner/repo", name="owner/repo")
        session.add(repo)
        session.commit()

        history = ScanHistory(
            repo_id=repo.id,
            status="running",
        )
        session.add(history)
        session.commit()

        assert history.id is not None
        assert history.status == "running"
        assert history.findings_count == 0

    def test_complete_scan(self, session):
        """Test completing a scan."""
        repo = Repository(url="https://github.com/owner/repo", name="owner/repo")
        session.add(repo)
        session.commit()

        history = ScanHistory(repo_id=repo.id)
        session.add(history)
        session.commit()

        history.status = "completed"
        history.findings_count = 5
        history.completed_at = datetime.utcnow()
        session.commit()

        assert history.status == "completed"
        assert history.findings_count == 5
        assert history.completed_at is not None
