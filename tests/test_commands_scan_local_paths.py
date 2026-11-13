"""Tests for scanning local repository paths through the CLI."""

import pytest
from typer.testing import CliRunner

from repoarmor.cli import commands
from repoarmor.config.settings import DatabaseConfig, Settings
from repoarmor.db.database import close_database


runner = CliRunner()


@pytest.mark.parametrize("relative_repo", ["myrepo", "parent/myrepo"])
def test_scan_keeps_existing_relative_git_repo_as_local_path(
    tmp_path, monkeypatch, relative_repo
):
    repo_path = tmp_path / relative_repo
    (repo_path / ".git").mkdir(parents=True)
    settings = Settings(database=DatabaseConfig(path=tmp_path / "scanner.db"))
    scanned_urls = []
    github_org_calls = []

    def fake_scan_repository(url, **kwargs):
        scanned_urls.append(url)
        return iter(())

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(commands, "setup_logging", lambda verbose=False: None)
    monkeypatch.setattr(commands, "ensure_trufflehog", lambda: True)
    monkeypatch.setattr(commands, "get_settings", lambda: settings)
    monkeypatch.setattr(commands, "scan_repository", fake_scan_repository)
    monkeypatch.setattr(
        commands,
        "_fetch_github_org_repos",
        lambda *args, **kwargs: github_org_calls.append(args) or [],
    )

    close_database()
    try:
        result = runner.invoke(commands.app, ["secret-scan", relative_repo])
    finally:
        close_database()

    assert result.exit_code == 0, result.output
    assert scanned_urls == [str(repo_path.resolve())]
    assert github_org_calls == []
