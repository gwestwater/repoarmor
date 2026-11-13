"""Tests for GitHub API client organization membership lookups."""

from repoarmor.scanner.github_api import GitHubClient


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, headers=None, ok=True):
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else []
        self.headers = headers or {}
        self.ok = ok

    def json(self):
        return self._json_data


def test_get_org_members_falls_back_when_members_endpoint_redirects(monkeypatch):
    client = GitHubClient(token="token", require_token=False)

    def fake_request(method, url, headers=None, **kwargs):
        assert method == "GET"
        assert url.endswith("/orgs/acme/members")
        assert kwargs["allow_redirects"] is False
        return FakeResponse(
            status_code=302,
            headers={"Location": "https://api.github.com/orgs/acme/public_members"},
        )

    monkeypatch.setattr("repoarmor.scanner.github_api.requests.request", fake_request)
    monkeypatch.setattr(client, "_paginate_public", lambda org: iter(["public-user"]))

    members_iter, public_only_used = client.get_org_members("acme")

    assert list(members_iter) == ["public-user"]
    assert public_only_used is True


def test_get_org_members_returns_full_list_without_redirect(monkeypatch):
    client = GitHubClient(token="token", require_token=False)

    def fake_request(method, url, headers=None, **kwargs):
        assert method == "GET"
        assert url.endswith("/orgs/acme/members")
        assert kwargs["allow_redirects"] is False
        return FakeResponse(json_data=[{"login": "alice"}])

    monkeypatch.setattr("repoarmor.scanner.github_api.requests.request", fake_request)

    members_iter, public_only_used = client.get_org_members("acme")

    assert list(members_iter) == ["alice"]
    assert public_only_used is False
