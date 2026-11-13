"""Tests for reusable workflow pipeline checks."""

import pytest

from repoarmor.scanner.github_api import GitHubAPIError
from repoarmor.scanner.pipeline_check import (
    _find_reusable_workflow_refs,
    _get_cached_workflow_content,
    check_repo_for_trufflehog,
    search_repo_workflows,
)


class FakeGitHubClient:
    """Small fake client for pipeline-check tests."""

    def __init__(
        self,
        *,
        repo_info=None,
        workflow_paths=None,
        file_contents=None,
        branch_rules=None,
        repo_by_id=None,
    ):
        self.repo_info = repo_info or {"visibility": "public", "default_branch": "main"}
        self.workflow_paths = workflow_paths or []
        self.file_contents = file_contents or {}
        self.branch_rules = branch_rules or []
        self.repo_by_id = repo_by_id or {}
        self.file_calls = []

    def get_repo_info(self, owner, repo):
        return self.repo_info

    def list_workflow_files(self, owner, repo, ref=None):
        return list(self.workflow_paths)

    def get_file_content(self, owner, repo, path, ref=None):
        self.file_calls.append((owner, repo, path, ref))
        value = self.file_contents[(owner, repo, path, ref)]
        if isinstance(value, Exception):
            raise value
        return value

    def get_branch_rules(self, owner, repo, branch):
        return list(self.branch_rules)

    def get_repo_by_id(self, repo_id):
        return self.repo_by_id[repo_id]


@pytest.fixture(autouse=True)
def clear_pipeline_caches():
    from repoarmor.scanner import pipeline_check

    pipeline_check._reusable_workflow_cache.clear()
    pipeline_check._repo_id_cache.clear()
    yield
    pipeline_check._reusable_workflow_cache.clear()
    pipeline_check._repo_id_cache.clear()


def test_find_reusable_workflow_refs_preserves_pinned_ref():
    content = """
jobs:
  reusable:
    uses: 'other-org/shared-ci/.github/workflows/trufflehog.yml@release/2026'
  local:
    uses: ./.github/workflows/local.yml
"""

    refs = _find_reusable_workflow_refs(content, "current-org", "current-repo")

    assert refs == [
        (
            "other-org",
            "shared-ci",
            ".github/workflows/trufflehog.yml",
            "release/2026",
        ),
        ("current-org", "current-repo", ".github/workflows/local.yml", None),
    ]


def test_cached_workflow_content_does_not_cache_api_errors():
    class FlakyGitHubClient:
        def __init__(self):
            self.calls = 0

        def get_file_content(self, owner, repo, path, ref=None):
            self.calls += 1
            if self.calls == 1:
                raise GitHubAPIError("temporary failure")
            return "content"

    github = FlakyGitHubClient()

    with pytest.raises(GitHubAPIError):
        _get_cached_workflow_content(github, "org", "repo", ".github/workflows/scan.yml", ref="main")

    assert _get_cached_workflow_content(github, "org", "repo", ".github/workflows/scan.yml", ref="main") == "content"
    assert github.calls == 2


def test_check_repo_for_trufflehog_follows_nested_reusable_workflows_with_refs():
    github = FakeGitHubClient(
        workflow_paths=[".github/workflows/main.yml"],
        file_contents={
            (
                "acme",
                "service",
                ".github/workflows/main.yml",
                None,
            ): """
on: pull_request
jobs:
  wrapper:
    uses: 'acme/security/.github/workflows/wrapper.yml@v2'
""",
            (
                "acme",
                "security",
                ".github/workflows/wrapper.yml",
                "v2",
            ): """
on:
  workflow_call:
jobs:
  nested:
    uses: acme/security/.github/workflows/scan.yml@release/2026
""",
            (
                "acme",
                "security",
                ".github/workflows/scan.yml",
                "release/2026",
            ): """
on:
  workflow_call:
jobs:
  scan:
    steps:
      - run: trufflehog git .
""",
        },
    )

    result = check_repo_for_trufflehog(github, "acme", "service")

    assert result.has_trufflehog is True
    assert result.pr_gated is True
    assert result.matched_files == [".github/workflows/main.yml"]
    assert ("acme", "security", ".github/workflows/wrapper.yml", "v2") in github.file_calls
    assert ("acme", "security", ".github/workflows/scan.yml", "release/2026") in github.file_calls


def test_check_repo_for_trufflehog_does_not_mark_pr_gated_when_job_excludes_pr():
    github = FakeGitHubClient(
        workflow_paths=[".github/workflows/main.yml"],
        file_contents={
            (
                "acme",
                "service",
                ".github/workflows/main.yml",
                None,
            ): """
on: pull_request
jobs:
  scan:
    if: github.event_name != 'pull_request'
    steps:
      - run: trufflehog filesystem .
""",
        },
    )

    result = check_repo_for_trufflehog(github, "acme", "service")

    assert result.has_trufflehog is True
    assert result.pr_gated is False
    assert result.matched_files == [".github/workflows/main.yml"]
    assert result.pr_gated_files == []


def test_search_repo_workflows_escapes_literal_patterns():
    github = FakeGitHubClient(
        workflow_paths=[".github/workflows/a.yml", ".github/workflows/b.yml"],
        file_contents={
            ("acme", "service", ".github/workflows/a.yml", None): "name: trufflehog[bot]\n",
            ("acme", "service", ".github/workflows/b.yml", None): "name: trufflehogbot\n",
        },
    )

    result = search_repo_workflows(github, "acme", "service", "trufflehog[bot]")

    assert result.found is True
    assert result.matched_files == [".github/workflows/a.yml"]
    assert result.workflow_count == 2
    assert result.error is None


def test_search_repo_workflows_supports_regex_patterns():
    github = FakeGitHubClient(
        workflow_paths=[".github/workflows/a.yml", ".github/workflows/b.yml"],
        file_contents={
            ("acme", "service", ".github/workflows/a.yml", None): "uses: actions/setup-python@v5\n",
            ("acme", "service", ".github/workflows/b.yml", None): "run: TruffleHog git .\n",
        },
    )

    result = search_repo_workflows(github, "acme", "service", r"trufflehog|gitleaks", use_regex=True)

    assert result.found is True
    assert result.matched_files == [".github/workflows/b.yml"]
    assert result.workflow_count == 2
    assert result.error is None


def test_search_repo_workflows_reports_invalid_regex():
    github = FakeGitHubClient(
        workflow_paths=[".github/workflows/a.yml"],
        file_contents={
            ("acme", "service", ".github/workflows/a.yml", None): "name: ci\n",
        },
    )

    result = search_repo_workflows(github, "acme", "service", "[", use_regex=True)

    assert result.found is False
    assert result.matched_files == []
    assert result.workflow_count == 1
    assert result.error is not None
    assert "Invalid regex pattern" in result.error


def test_search_repo_workflows_reports_file_read_failures():
    github = FakeGitHubClient(
        workflow_paths=[".github/workflows/a.yml", ".github/workflows/b.yml"],
        file_contents={
            ("acme", "service", ".github/workflows/a.yml", None): "name: ci\n",
            ("acme", "service", ".github/workflows/b.yml", None): GitHubAPIError("boom"),
        },
    )

    result = search_repo_workflows(github, "acme", "service", "trufflehog")

    assert result.found is False
    assert result.matched_files == []
    assert result.workflow_count == 2
    assert result.error == "Could not read workflow '.github/workflows/b.yml': boom"


def test_required_workflow_only_sets_org_flag_for_org_rulesets():
    github = FakeGitHubClient(
        workflow_paths=[],
        file_contents={
            (
                "acme",
                "security",
                ".github/workflows/required.yml",
                "main",
            ): """
on:
  workflow_call:
jobs:
  scan:
    steps:
      - uses: trufflesecurity/trufflehog@main
""",
        },
        branch_rules=[
            {
                "type": "workflows",
                "ruleset_source_type": "Repository",
                "ruleset_source": "acme/service",
                "parameters": {
                    "workflows": [
                        {
                            "path": ".github/workflows/required.yml",
                            "repository_id": 42,
                            "ref": "refs/heads/main",
                        }
                    ]
                },
            }
        ],
        repo_by_id={42: {"full_name": "acme/security"}},
    )

    result = check_repo_for_trufflehog(github, "acme", "service")

    assert result.has_trufflehog is True
    assert result.pr_gated is True
    assert result.org_ruleset_enforced is False
