"""Tests for repository visibility resolution during scans."""

import pytest
from sqlalchemy import select

from repoarmor.cli import commands
from repoarmor.config.settings import DatabaseConfig, Settings
from repoarmor.db.database import close_database, session_scope
from repoarmor.db.models import Repository


def test_resolve_github_visibility_returns_none_when_lookup_fails(monkeypatch):
    class FailingGitHubClient:
        def __init__(self, **kwargs):
            pass

        def get_repo_info(self, owner, repo):
            raise RuntimeError("API unavailable")

    monkeypatch.setattr(commands, "GitHubClient", FailingGitHubClient)

    assert commands._resolve_github_visibility("https://github.com/acme/project", None) is None


def test_resolve_github_visibility_keeps_non_github_fallback():
    assert commands._resolve_github_visibility("https://bitbucket.org/acme/project", None) == "public"


@pytest.mark.parametrize(
    ("repo_info", "expected_visibility"),
    [
        ({"visibility": "private", "private": True}, "private"),
        ({"visibility": "internal", "private": True}, "internal"),
        ({"private": True}, "private"),
    ],
)
def test_resolve_github_visibility_returns_api_visibility(
    monkeypatch, repo_info, expected_visibility
):
    class MockGitHubClient:
        def __init__(self, **kwargs):
            pass

        def get_repo_info(self, owner, repo):
            return repo_info

    monkeypatch.setattr(commands, "GitHubClient", MockGitHubClient)

    assert (
        commands._resolve_github_visibility(
            "https://github.com/acme/project", None
        )
        == expected_visibility
    )


@pytest.mark.parametrize(
    ("scan_mode", "repo_info", "expected_visibility"),
    [
        ("direct", {"visibility": "internal", "private": True}, "internal"),
        ("batch", {"private": True}, "private"),
    ],
)
def test_scan_persists_resolved_visibility_for_direct_and_batch(
    tmp_path, monkeypatch, scan_mode, repo_info, expected_visibility
):
    close_database()
    settings = Settings(database=DatabaseConfig(path=tmp_path / "scanner.db"))
    repo_url = "https://github.com/acme/project"

    class MockGitHubClient:
        def __init__(self, **kwargs):
            pass

        def get_repo_info(self, owner, repo):
            assert (owner, repo) == ("acme", "project")
            return repo_info

    monkeypatch.setattr(commands, "GitHubClient", MockGitHubClient)
    monkeypatch.setattr(commands, "get_settings", lambda: settings)
    monkeypatch.setattr(commands, "ensure_trufflehog", lambda: True)
    monkeypatch.setattr(commands, "setup_logging", lambda verbose=False: None)
    monkeypatch.setattr(commands, "scan_repository", lambda *args, **kwargs: iter(()))

    batch_file = None
    repo_urls = [repo_url]
    if scan_mode == "batch":
        batch_file = tmp_path / "repos.txt"
        batch_file.write_text(repo_url)
        repo_urls = None

    try:
        commands.scan(
            repo_urls=repo_urls,
            batch=batch_file,
            org=None,
            user=None,
            user_org=None,
            user_orgs=None,
            azure_org=None,
            bb_workspace=None,
            bb_server_project=None,
            bb_server_url=None,
            token=None,
            include_archived=False,
            include_private=True,
            depth=None,
            branch=None,
            only_verified=False,
            verbose=False,
        )

        with session_scope() as session:
            repo = session.execute(
                select(Repository).where(Repository.url == repo_url)
            ).scalar_one()
            assert repo.visibility == expected_visibility
    finally:
        close_database()
