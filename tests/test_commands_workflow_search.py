"""Tests for workflow search CLI commands."""

from typer.testing import CliRunner

from repoarmor.cli import commands
from repoarmor.scanner.github_api import GitHubRepo
from repoarmor.scanner.pipeline_check import PipelineCheckResult, WorkflowSearchResult


runner = CliRunner()


def test_search_repo_workflows_rejects_invalid_regex_before_fanout(monkeypatch):
    monkeypatch.setattr(commands, "setup_logging", lambda verbose=False: None)
    monkeypatch.setattr(
        commands,
        "GitHubClient",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("GitHubClient should not be created")),
    )

    result = runner.invoke(
        commands.app,
        [
            "search-repo-workflows",
            "acme/repo-one",
            "acme/repo-two",
            "--pattern",
            "[",
            "--regex",
        ],
    )

    assert result.exit_code == 1
    assert "Invalid regex pattern" in result.output


def test_search_org_workflows_rejects_invalid_regex_before_fanout(monkeypatch):
    monkeypatch.setattr(commands, "setup_logging", lambda verbose=False: None)
    monkeypatch.setattr(
        commands,
        "GitHubClient",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("GitHubClient should not be created")),
    )

    result = runner.invoke(
        commands.app,
        [
            "search-org-workflows",
            "acme",
            "--pattern",
            "[",
            "--regex",
        ],
    )

    assert result.exit_code == 1
    assert "Invalid regex pattern" in result.output


class _FakeGitHubClient:
    def validate_org_access(self, org):
        return True

    def get_org_repos(self, org, include_private=False, include_archived=False):
        return [
            GitHubRepo(
                name="service",
                full_name=f"{org}/service",
                url=f"https://github.com/{org}/service",
                clone_url=f"https://github.com/{org}/service.git",
                visibility="public",
                archived=False,
                default_branch="main",
            )
        ]


def test_check_org_pipeline_branch_mode_reports_branch_checks(monkeypatch):
    monkeypatch.setattr(commands, "setup_logging", lambda verbose=False: None)
    monkeypatch.setattr(commands, "GitHubClient", lambda *args, **kwargs: _FakeGitHubClient())
    monkeypatch.setattr(commands, "render_pipeline_check_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        commands,
        "_check_repo_across_branches",
        lambda *args, **kwargs: [
            PipelineCheckResult(
                repo_full_name="acme/service",
                repo_url="https://github.com/acme/service",
                has_trufflehog=False,
                visibility="public",
                branch="release/1.0",
            ),
            PipelineCheckResult(
                repo_full_name="acme/service",
                repo_url="https://github.com/acme/service",
                has_trufflehog=False,
                visibility="public",
                branch="release/2.0",
            ),
        ],
    )

    result = runner.invoke(
        commands.app,
        [
            "check-org-pipeline",
            "acme",
            "--branch",
            "release/1.0",
            "--branch",
            "release/2.0",
        ],
    )

    assert result.exit_code == 0
    assert "2 branch checks don't run TruffleHog on pull requests." in result.output


def test_search_org_workflows_branch_mode_reports_branch_checks(monkeypatch):
    monkeypatch.setattr(commands, "setup_logging", lambda verbose=False: None)
    monkeypatch.setattr(commands, "GitHubClient", lambda *args, **kwargs: _FakeGitHubClient())
    monkeypatch.setattr(commands, "render_workflow_search_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        commands,
        "_search_repo_workflows_across_branches",
        lambda *args, **kwargs: [
            WorkflowSearchResult(
                repo_full_name="acme/service",
                repo_url="https://github.com/acme/service",
                found=True,
                visibility="public",
                branch="release/1.0",
            ),
            WorkflowSearchResult(
                repo_full_name="acme/service",
                repo_url="https://github.com/acme/service",
                found=False,
                visibility="public",
                branch="release/2.0",
            ),
        ],
    )

    result = runner.invoke(
        commands.app,
        [
            "search-org-workflows",
            "acme",
            "--pattern",
            "needle",
            "--branch",
            "release/1.0",
            "--branch",
            "release/2.0",
        ],
    )

    assert result.exit_code == 0
    assert "'needle' found in 1 of 2 branch checks searched." in result.output


def test_search_org_workflows_found_only_summary_matches_filtered_branch_results(monkeypatch):
    monkeypatch.setattr(commands, "setup_logging", lambda verbose=False: None)
    monkeypatch.setattr(commands, "GitHubClient", lambda *args, **kwargs: _FakeGitHubClient())
    monkeypatch.setattr(commands, "render_workflow_search_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        commands,
        "_search_repo_workflows_across_branches",
        lambda *args, **kwargs: [
            WorkflowSearchResult(
                repo_full_name="acme/service",
                repo_url="https://github.com/acme/service",
                found=True,
                visibility="public",
                branch="release/1.0",
            ),
            WorkflowSearchResult(
                repo_full_name="acme/service",
                repo_url="https://github.com/acme/service",
                found=False,
                visibility="public",
                branch="release/2.0",
            ),
        ],
    )

    result = runner.invoke(
        commands.app,
        [
            "search-org-workflows",
            "acme",
            "--pattern",
            "needle",
            "--branch",
            "release/1.0",
            "--branch",
            "release/2.0",
            "--found-only",
        ],
    )

    assert result.exit_code == 0
    assert "'needle' found in 1 of 2 branch checks searched." in result.output
