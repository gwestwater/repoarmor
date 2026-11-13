"""Tests for CLI auth URL injection helpers."""

from repoarmor.cli.commands import _inject_auth_token, _inject_url_auth


def test_inject_auth_token_encodes_bitbucket_cloud_credentials(monkeypatch):
    monkeypatch.setenv("BITBUCKET_USERNAME", "user:name")
    monkeypatch.setenv("BITBUCKET_APP_PASSWORD", "tok@en/with#chars")

    url = _inject_auth_token("https://bitbucket.org/team/repo.git")

    assert url == "https://user%3Aname:tok%40en%2Fwith%23chars@bitbucket.org/team/repo.git"


def test_inject_auth_token_supports_http_azure_urls(monkeypatch):
    monkeypatch.setenv("AZURE_DEVOPS_TOKEN", "pa:t/with@chars")

    url = _inject_auth_token("http://orgname@dev.azure.com/org/project/_git/repo")

    assert url == "http://pat:pa%3At%2Fwith%40chars@dev.azure.com/org/project/_git/repo"


def test_inject_auth_token_encodes_bitbucket_server_credentials(monkeypatch):
    monkeypatch.setenv("BITBUCKET_SERVER_USERNAME", "svc:user")
    monkeypatch.setenv("BITBUCKET_SERVER_TOKEN", "tok#en/1")

    url = _inject_auth_token("https://code.example.com/scm/PROJ/repo.git")

    assert url == "https://svc%3Auser:tok%23en%2F1@code.example.com/scm/PROJ/repo.git"


def test_inject_auth_token_keeps_existing_credentials():
    url = _inject_auth_token("https://alice:secret@bitbucket.org/team/repo.git")
    assert url == "https://alice:secret@bitbucket.org/team/repo.git"


def test_inject_url_auth_keeps_existing_credentials():
    url = _inject_url_auth("https://alice:secret@code.example.com/scm/PROJ/repo.git", "pat", "new-token")
    assert url == "https://alice:secret@code.example.com/scm/PROJ/repo.git"


def test_inject_auth_token_injects_github_token_from_env(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken123")
    monkeypatch.delenv("BITBUCKET_APP_PASSWORD", raising=False)

    url = _inject_auth_token("https://github.com/acme/service")

    assert url == "https://x-access-token:ghp_testtoken123@github.com/acme/service"


def test_inject_auth_token_injects_github_token_from_arg(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    url = _inject_auth_token("https://github.com/acme/service", token="ghp_explicit")

    assert url == "https://x-access-token:ghp_explicit@github.com/acme/service"


def test_inject_auth_token_skips_github_without_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    url = _inject_auth_token("https://github.com/owner/repo")

    assert url == "https://github.com/owner/repo"


def test_inject_auth_token_arg_token_takes_precedence_over_env(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_from_env")

    url = _inject_auth_token("https://github.com/owner/repo", token="ghp_from_arg")

    assert url == "https://x-access-token:ghp_from_arg@github.com/owner/repo"
