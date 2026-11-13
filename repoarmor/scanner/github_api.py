"""GitHub API client for fetching organization repositories."""

import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator
from urllib.parse import quote

import requests


class _RateLimiter:
    """Thread-safe sliding-window limiter, used to stay under GitHub's Search API
    rate limit (30 req/min authenticated, 10 req/min unauthenticated) - without it,
    concurrent lookups get 403'd and those failures get silently treated as 'no data'.
    """

    def __init__(self, max_requests: int, window_seconds: float = 60.0):
        self._max_requests = max_requests
        self._window = window_seconds
        self._lock = threading.Lock()
        self._timestamps: list[float] = []

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            self._timestamps = [t for t in self._timestamps if now - t < self._window]
            if len(self._timestamps) >= self._max_requests:
                sleep_for = self._window - (now - self._timestamps[0]) + 0.1
                if sleep_for > 0:
                    time.sleep(sleep_for)
                now = time.monotonic()
                self._timestamps = [t for t in self._timestamps if now - t < self._window]
            self._timestamps.append(now)


@dataclass
class GitHubRepo:
    """Represents a GitHub repository."""
    name: str
    full_name: str
    url: str
    clone_url: str
    visibility: str  # public, private, internal
    archived: bool
    default_branch: str


class GitHubAPIError(Exception):
    """Error from GitHub API."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_kind: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_kind = error_kind


class GitHubClient:
    """Client for GitHub API operations."""

    BASE_URL = "https://api.github.com"
    GRAPHQL_URL = "https://api.github.com/graphql"

    def __init__(self, token: str | None = None, require_token: bool = True):
        """Initialize the GitHub client.

        Args:
            token: GitHub personal access token. If not provided,
                   uses GITHUB_TOKEN environment variable.
            require_token: If True, raise when no token is available. Set to
                   False for public-only endpoints (e.g. listing a user's
                   public repositories), where a token is optional and only
                   used to raise rate limits.
        """
        self.token = token or os.environ.get("GITHUB_TOKEN")
        if not self.token and require_token:
            raise GitHubAPIError(
                "GitHub token required. Set GITHUB_TOKEN environment variable "
                "or provide --token option."
            )
        # Leave a safety margin under GitHub's published Search API limits.
        self._search_rate_limiter = _RateLimiter(max_requests=25 if self.token else 8)

    def _get_headers(self) -> dict:
        """Get headers for API requests."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    @staticmethod
    def _describe_forbidden(response) -> str:
        """Turn a 403 response into a specific message, since GitHub uses 403 for
        both rate limiting and permission/SSO issues (which need different fixes).
        """
        if response.headers.get("Retry-After"):
            return f"Secondary rate limit hit. Retry after {response.headers['Retry-After']}s."
        if response.headers.get("X-RateLimit-Remaining") == "0":
            reset = response.headers.get("X-RateLimit-Reset")
            if reset:
                reset_time = datetime.fromtimestamp(int(reset)).strftime("%H:%M:%S")
                return f"Primary rate limit exceeded. Resets at {reset_time}."
            return "Primary rate limit exceeded."
        try:
            message = response.json().get("message", "")
        except Exception:
            message = ""
        if "saml" in message.lower():
            return "Access forbidden: organization requires SSO authorization for this token."
        return "Access forbidden (not rate limited). Token likely lacks access to this repository/org."

    def _request(
        self, method: str, endpoint: str, not_found_ok: bool = False, **kwargs
    ) -> dict | list | None:
        """Make an API request.

        Args:
            not_found_ok: If True, return None on 404 instead of raising.
        """
        response = self._send_request(method, endpoint, **kwargs)
        return self._parse_response(response, endpoint, not_found_ok=not_found_ok)

    def _send_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Send a GitHub API request and return the raw response."""
        url = f"{self.BASE_URL}{endpoint}"
        return requests.request(
            method,
            url,
            headers=self._get_headers(),
            **kwargs
        )

    def _parse_response(
        self, response: requests.Response, endpoint: str, *, not_found_ok: bool = False
    ) -> dict | list | None:
        """Validate and decode a GitHub API response."""
        if response.status_code == 401:
            raise GitHubAPIError(
                "Invalid GitHub token or token lacks required permissions.",
                status_code=401,
                error_kind="auth",
            )
        elif response.status_code == 403:
            error_kind = (
                "rate_limit"
                if response.headers.get("Retry-After")
                or response.headers.get("X-RateLimit-Remaining") == "0"
                else "forbidden"
            )
            raise GitHubAPIError(
                self._describe_forbidden(response),
                status_code=403,
                error_kind=error_kind,
            )
        elif response.status_code == 404:
            if not_found_ok:
                return None
            raise GitHubAPIError(f"Resource not found: {endpoint}", status_code=404, error_kind="not_found")
        elif not response.ok:
            # Sanitize error message - don't expose full API response which may contain sensitive info
            raise GitHubAPIError(
                f"GitHub API error: HTTP {response.status_code}",
                status_code=response.status_code,
                error_kind="http_error",
            )

        return response.json()

    def get_repo_contents(self, owner: str, repo: str, path: str, ref: str | None = None) -> list | dict | None:
        """Fetch the contents of a path in a repository (file or directory listing).

        Returns None if the path does not exist (e.g. no workflows directory).
        """
        endpoint = f"/repos/{owner}/{repo}/contents/{path}"
        params = {"ref": ref} if ref else None
        return self._request("GET", endpoint, not_found_ok=True, params=params)

    def get_repo_info(self, owner: str, repo: str) -> dict | None:
        """Fetch repository metadata (visibility, default branch, etc.).

        Returns None if the repository does not exist or is not accessible.
        """
        return self._request("GET", f"/repos/{owner}/{repo}", not_found_ok=True)

    def get_file_content(self, owner: str, repo: str, path: str, ref: str | None = None) -> str | None:
        """Fetch and decode the text content of a single file in a repository.

        Returns None if the file does not exist or cannot be decoded as text.
        """
        import base64

        data = self.get_repo_contents(owner, repo, path, ref=ref)
        if not data or not isinstance(data, dict):
            return None
        content = data.get("content")
        encoding = data.get("encoding")
        if not content or encoding != "base64":
            return None
        try:
            return base64.b64decode(content).decode("utf-8", errors="replace")
        except Exception:
            return None

    def list_workflow_files(self, owner: str, repo: str, ref: str | None = None) -> list[str]:
        """List workflow file paths under .github/workflows for a repository.

        Returns an empty list if the directory does not exist.
        """
        listing = self.get_repo_contents(owner, repo, ".github/workflows", ref=ref)
        if not listing or not isinstance(listing, list):
            return []
        return [
            entry["path"]
            for entry in listing
            if entry.get("type") == "file" and entry.get("name", "").endswith((".yml", ".yaml"))
        ]

    def list_branches(self, owner: str, repo: str) -> list[str]:
        """List all branch names in a repository (paginated)."""
        branches: list[str] = []
        page = 1
        per_page = 100
        while True:
            endpoint = f"/repos/{owner}/{repo}/branches"
            params = {"per_page": per_page, "page": page}
            data = self._request("GET", endpoint, params=params, not_found_ok=True)
            if not data:
                break
            branches.extend(entry["name"] for entry in data)
            if len(data) < per_page:
                break
            page += 1
        return branches

    def get_branch_rules(self, owner: str, repo: str, branch: str) -> list[dict]:
        """Fetch the effective rules that apply to a branch, including ones inherited

        from org-level rulesets (e.g. a required workflow). Unlike listing org
        rulesets directly, this only needs normal read access to the repository -
        no organization admin permission required. The branch does not need to exist.
        """
        encoded_branch = quote(branch, safe="")
        result = self._request("GET", f"/repos/{owner}/{repo}/rules/branches/{encoded_branch}", not_found_ok=True)
        return result if isinstance(result, list) else []

    def get_repo_by_id(self, repo_id: int) -> dict | None:
        """Resolve a numeric repository ID to its metadata (e.g. full_name).

        Ruleset "required workflow" rules reference the reusable workflow's
        repository by ID rather than by owner/name.
        """
        return self._request("GET", f"/repositories/{repo_id}", not_found_ok=True)

    def get_org_repos(
        self,
        org: str,
        include_private: bool = True,
        include_archived: bool = False,
        repo_type: str = "all",
    ) -> Iterator[GitHubRepo]:
        """Fetch all repositories for an organization.

        Args:
            org: Organization name.
            include_private: Include private repositories.
            include_archived: Include archived repositories.
            repo_type: Type of repos to fetch ('all', 'public', 'private', 'forks', 'sources', 'member').

        Yields:
            GitHubRepo objects.
        """
        page = 1
        per_page = 100

        while True:
            endpoint = f"/orgs/{org}/repos"
            params = {
                "type": repo_type,
                "per_page": per_page,
                "page": page,
                "sort": "updated",
                "direction": "desc",
            }

            repos = self._request("GET", endpoint, params=params)

            if not repos:
                break

            for repo_data in repos:
                # Skip archived repos if not requested
                if repo_data.get("archived") and not include_archived:
                    continue

                # Skip private repos if not requested
                if repo_data.get("private") and not include_private:
                    continue

                # Get visibility: GitHub API returns "public", "private", or "internal"
                # Fallback to deriving from private field for older API responses
                visibility = repo_data.get("visibility")
                if not visibility:
                    visibility = "private" if repo_data.get("private", False) else "public"

                yield GitHubRepo(
                    name=repo_data["name"],
                    full_name=repo_data["full_name"],
                    url=repo_data["html_url"],
                    clone_url=repo_data["clone_url"],
                    visibility=visibility,
                    archived=repo_data.get("archived", False),
                    default_branch=repo_data.get("default_branch", "main"),
                )

            # Check if there are more pages
            if len(repos) < per_page:
                break

            page += 1

    def get_user_repos(
        self,
        username: str | None = None,
        include_private: bool = True,
        include_archived: bool = False,
    ) -> Iterator[GitHubRepo]:
        """Fetch repositories for a user (or authenticated user if no username).

        Args:
            username: GitHub username. If None, fetches authenticated user's repos.
            include_private: Include private repositories.
            include_archived: Include archived repositories.

        Yields:
            GitHubRepo objects.
        """
        page = 1
        per_page = 100

        while True:
            if username:
                endpoint = f"/users/{username}/repos"
            else:
                endpoint = "/user/repos"

            params = {
                "per_page": per_page,
                "page": page,
                "sort": "updated",
                "direction": "desc",
            }

            if not username:
                params["affiliation"] = "owner,collaborator,organization_member"

            repos = self._request("GET", endpoint, params=params)

            if not repos:
                break

            for repo_data in repos:
                if repo_data.get("archived") and not include_archived:
                    continue

                if repo_data.get("private") and not include_private:
                    continue

                # Get visibility: GitHub API returns "public", "private", or "internal"
                visibility = repo_data.get("visibility")
                if not visibility:
                    visibility = "private" if repo_data.get("private", False) else "public"

                yield GitHubRepo(
                    name=repo_data["name"],
                    full_name=repo_data["full_name"],
                    url=repo_data["html_url"],
                    clone_url=repo_data["clone_url"],
                    visibility=visibility,
                    archived=repo_data.get("archived", False),
                    default_branch=repo_data.get("default_branch", "main"),
                )

            if len(repos) < per_page:
                break

            page += 1

    def get_org_members(self, org: str, public_only: bool = False) -> tuple[Iterator[str], bool]:
        """Fetch org member logins. Falls back to public members if not authorized.

        Returns:
            (iterator of logins, public_only_fallback_used)
        """
        endpoint = f"/orgs/{org}/{'public_members' if public_only else 'members'}"

        def _paginate(ep: str):
            page = 1
            per_page = 100
            while True:
                response = self._send_request(
                    "GET",
                    ep,
                    params={"per_page": per_page, "page": page},
                    allow_redirects=False,
                )
                if (
                    not public_only
                    and response.status_code in (301, 302, 307, 308)
                    and "/public_members" in response.headers.get("Location", "")
                ):
                    raise GitHubAPIError(
                        "Redirected to public members listing.",
                        status_code=response.status_code,
                        error_kind="public_members_redirect",
                    )
                members = self._parse_response(response, ep)
                if not members:
                    break
                for member in members:
                    yield member["login"]
                if len(members) < per_page:
                    break
                page += 1

        if public_only:
            return _paginate(endpoint), True

        # Try full member list; fall back to unauthenticated public members on auth failure or empty result
        try:
            members = list(_paginate(endpoint))
            if members:
                return iter(members), False
            # Empty result means non-member account (GitHub returns 200 [] for non-members)
            return self._paginate_public(org), True
        except GitHubAPIError as e:
            if e.error_kind == "public_members_redirect":
                return self._paginate_public(org), True
            if e.status_code in (401, 403) and e.error_kind != "rate_limit":
                return self._paginate_public(org), True
            raise

    def _paginate_public(self, org: str) -> Iterator[str]:
        """Fetch public org members without auth (works even with an invalid/missing token)."""
        page = 1
        per_page = 100
        base_headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        while True:
            response = requests.get(
                f"{self.BASE_URL}/orgs/{org}/public_members",
                headers=base_headers,
                params={"per_page": per_page, "page": page},
                timeout=30,
            )
            if response.status_code == 401:
                raise GitHubAPIError(
                    "Invalid GitHub token or token lacks required permissions.",
                    status_code=401,
                    error_kind="auth",
                )
            if response.status_code == 403:
                error_kind = (
                    "rate_limit"
                    if response.headers.get("Retry-After")
                    or response.headers.get("X-RateLimit-Remaining") == "0"
                    else "forbidden"
                )
                raise GitHubAPIError(
                    self._describe_forbidden(response),
                    status_code=403,
                    error_kind=error_kind,
                )
            if response.status_code == 404:
                raise GitHubAPIError(
                    f"Resource not found: /orgs/{org}/public_members",
                    status_code=404,
                    error_kind="not_found",
                )
            if not response.ok:
                raise GitHubAPIError(
                    f"GitHub API error: HTTP {response.status_code}",
                    status_code=response.status_code,
                    error_kind="http_error",
                )

            members = response.json()
            if not members:
                break
            for member in members:
                yield member["login"]
            if len(members) < per_page:
                break
            page += 1

    def validate_org_access(self, org: str) -> bool:
        """Check if the token has access to the organization.

        Args:
            org: Organization name.

        Returns:
            True if the org exists and is accessible.
        """
        try:
            self._request("GET", f"/orgs/{org}")
            return True
        except GitHubAPIError:
            return False

    def get_org_default_permission(self, org: str) -> str | None:
        """Fetch the org's default repository permission ('read', 'write', 'admin', or 'none').

        This is the access level every org member gets on every repo in the org unless
        overridden - the setting responsible for org members implicitly appearing as repo
        "collaborators" even when never explicitly added. Only visible to organization
        owners (OAuth/classic PAT needs the admin:org scope); returns None otherwise.
        """
        data = self._request("GET", f"/orgs/{org}", not_found_ok=True)
        if not isinstance(data, dict):
            return None
        return data.get("default_repository_permission")

    def get_repo_collaborators(self, owner: str, repo: str, affiliation: str = "all") -> Iterator[str]:
        """Fetch collaborator logins for a repository.

        Args:
            affiliation: 'outside' for collaborators who aren't org members, 'direct'
                for those added directly to the repo, or 'all' (default).
        """
        page = 1
        per_page = 100
        while True:
            collaborators = self._request(
                "GET", f"/repos/{owner}/{repo}/collaborators",
                params={"affiliation": affiliation, "per_page": per_page, "page": page},
                not_found_ok=True,
            )
            if not collaborators:
                break
            for collaborator in collaborators:
                yield collaborator["login"]
            if len(collaborators) < per_page:
                break
            page += 1

    def get_user_profile_email(self, username: str) -> str | None:
        """Fetch a user's public profile email, if they've chosen to make one visible."""
        data = self._request("GET", f"/users/{username}", not_found_ok=True)
        if not isinstance(data, dict):
            return None
        email = data.get("email")
        return email if isinstance(email, str) and email else None

    def _graphql(self, query: str, variables: dict) -> dict | None:
        """Execute a GraphQL query. Returns the 'data' object, or None on any error."""
        try:
            response = requests.post(
                self.GRAPHQL_URL,
                headers=self._get_headers(),
                json={"query": query, "variables": variables},
                timeout=30,
            )
        except requests.RequestException:
            return None
        if not response.ok:
            return None
        payload = response.json()
        if payload.get("errors"):
            return None
        return payload.get("data")

    def get_verified_domain_emails(self, username: str, org: str) -> list[str]:
        """Fetch email(s) a user has verified on GitHub that match one of an org's verified domains.

        This only returns results if the org has configured verified domains (e.g. example.com)
        and the user has added+verified a matching email on their GitHub account - GitHub's own
        mechanism for identifying org-affiliated users. Returns an empty list (not an error) when
        unavailable, since most orgs/users won't have this set up.
        """
        query = """
        query($login: String!, $org: String!) {
          user(login: $login) {
            organizationVerifiedDomainEmails(login: $org)
          }
        }
        """
        data = self._graphql(query, {"login": username, "org": org})
        if not data or not data.get("user"):
            return []
        return data["user"].get("organizationVerifiedDomainEmails") or []

    def get_scim_user_email(self, org: str, username: str) -> str | None:
        """Fetch a member's email from the org's SCIM-provisioned identity, if one exists.

        Only works for GitHub Enterprise Cloud orgs with SAML SSO + SCIM provisioning
        (e.g. via Okta/Entra ID), and requires the token to belong to an org owner.
        Returns None (not an error) when unavailable, since most orgs don't use SCIM.
        """
        try:
            result = self._request(
                "GET", f"/scim/v2/organizations/{org}/Users",
                params={"filter": f'userName eq "{username}"'},
                not_found_ok=True,
            )
        except GitHubAPIError:
            return None
        if not isinstance(result, dict):
            return None

        resources = result.get("Resources") or []
        if not resources:
            return None
        emails = resources[0].get("emails") or []
        if not emails:
            return None
        primary = next((e["value"] for e in emails if e.get("primary") and e.get("value")), None)
        return primary or emails[0].get("value")

    def search_commit_author_emails(self, username: str, org: str | None = None, repo: str | None = None) -> list[str]:
        """Find a user's git commit author email(s) by searching their commits.

        This reads the raw git commit author email (set locally via `git config user.email`),
        which is often a corporate email even when the user's GitHub profile email is private.
        Different commits can carry different author emails (e.g. a personal address on some,
        a corporate address on others), so all distinct emails found are returned - not just
        the first - in the order first seen, so callers can check each against internal domains.
        Only searches each repository's default branch (a Search API limitation).

        Args:
            org: Restrict the search to a single organization's repos. If omitted (along with
                repo), searches every repository the token can see.
            repo: Restrict the search to a single 'owner/repo' (takes precedence over org).
        """
        query = f"author:{username}"
        if repo:
            query += f" repo:{repo}"
        elif org:
            query += f" org:{org}"

        self._search_rate_limiter.acquire()
        try:
            result = self._request(
                "GET", "/search/commits", params={"q": query, "per_page": 25}, not_found_ok=True
            )
        except GitHubAPIError:
            return []
        if not isinstance(result, dict):
            return []

        emails: list[str] = []
        for item in result.get("items", []):
            email = item.get("commit", {}).get("author", {}).get("email")
            # Skip GitHub's private "noreply" placeholder - it doesn't identify a real domain
            if email and "noreply.github.com" not in email and email not in emails:
                emails.append(email)
        return emails
