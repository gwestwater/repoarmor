"""Bitbucket Server (self-hosted) API client for fetching project repositories."""

import os
from dataclasses import dataclass
from typing import Iterator
from urllib.parse import quote

import requests


@dataclass
class BitbucketServerRepo:
    """Represents a Bitbucket Server repository."""
    name: str
    full_name: str  # PROJECT/repo
    url: str  # web URL
    clone_url: str  # HTTPS clone URL (scm path)
    visibility: str  # public, private
    is_archived: bool
    default_branch: str


class BitbucketServerAPIError(Exception):
    """Error from Bitbucket Server API."""
    pass


class BitbucketServerClient:
    """Client for Bitbucket Server REST API (1.0) operations.

    Supports scanning all repositories within a project.

    Auth options (in order of precedence):
        1. Explicit token parameter
        2. BITBUCKET_SERVER_TOKEN env var

    Requires BITBUCKET_SERVER_USERNAME for auth (defaults to "pat").

    Create HTTP access tokens at:
        https://<server>/plugins/servlet/access-tokens/manage
    Required permissions: Repository read
    """

    def __init__(
        self,
        server_url: str,
        token: str | None = None,
        username: str | None = None,
    ):
        # Normalize server URL (remove trailing slash)
        self.server_url = server_url.rstrip("/")
        self.base_url = f"{self.server_url}/rest/api/1.0"

        self.token = token or os.environ.get("BITBUCKET_SERVER_TOKEN")
        self.username = username or os.environ.get("BITBUCKET_SERVER_USERNAME", "pat")

        if not self.token:
            raise BitbucketServerAPIError(
                "Bitbucket Server authentication required.\n"
                "  Set BITBUCKET_SERVER_TOKEN env var (HTTP access token)\n"
                "  Optionally set BITBUCKET_SERVER_USERNAME (defaults to 'pat')\n"
                "  Create token at: https://<server>/plugins/servlet/access-tokens/manage"
            )

    def _request(self, url: str, **kwargs) -> dict:
        """Make an API request with Basic auth (username:token)."""
        response = requests.get(
            url,
            auth=(self.username, self.token),
            **kwargs,
        )

        if response.status_code == 401:
            raise BitbucketServerAPIError(
                "Invalid Bitbucket Server credentials. Check your HTTP access token."
            )
        elif response.status_code == 403:
            raise BitbucketServerAPIError(
                "Access forbidden. Check that your token has 'Repository read' permission."
            )
        elif response.status_code == 404:
            raise BitbucketServerAPIError(
                "Project not found. Check the project key and server URL."
            )
        elif not response.ok:
            raise BitbucketServerAPIError(
                f"Bitbucket Server API error: HTTP {response.status_code}"
            )

        return response.json()

    def _paginate(self, url: str, **kwargs) -> Iterator[dict]:
        """Handle Bitbucket Server's paginated responses.

        Bitbucket Server uses start/limit pagination with isLastPage flag.
        """
        start = 0
        while True:
            params = kwargs.pop("params", {})
            params["start"] = start
            params["limit"] = 100

            data = self._request(url, params=params, **kwargs)
            yield from data.get("values", [])

            if data.get("isLastPage", True):
                break
            start = data.get("nextPageStart", start + 100)

    def get_project_repos(
        self,
        project_key: str,
        include_private: bool = True,
        include_archived: bool = False,
    ) -> Iterator[BitbucketServerRepo]:
        """Fetch all repositories for a project.

        Args:
            project_key: Bitbucket Server project key (e.g., PLATFORM).
            include_private: Include private repositories.
            include_archived: Include archived repositories.

        Yields:
            BitbucketServerRepo objects.
        """
        url = f"{self.base_url}/projects/{quote(project_key)}/repos"

        for repo_data in self._paginate(url):
            # Check archived status
            is_archived = repo_data.get("archived", False)
            if is_archived and not include_archived:
                continue

            # Visibility
            is_public = repo_data.get("public", False)
            visibility = "public" if is_public else "private"
            if not include_private and not is_public:
                continue

            # Repo slug/name
            slug = repo_data.get("slug", repo_data.get("name", ""))
            full_name = f"{project_key}/{slug}"

            # Build clone URL: https://server/scm/PROJECT/repo.git
            clone_url = f"{self.server_url}/scm/{project_key}/{slug}"

            # Also check for clone URLs in the links
            for clone_link in repo_data.get("links", {}).get("clone", []):
                if clone_link.get("name") == "http" or clone_link.get("name") == "https":
                    clone_url = clone_link["href"]
                    # Remove .git suffix if present for consistency
                    if clone_url.endswith(".git"):
                        clone_url = clone_url[:-4]
                    break

            # Web URL
            web_url = ""
            for self_link in repo_data.get("links", {}).get("self", []):
                web_url = self_link.get("href", "")
                break
            if not web_url:
                web_url = f"{self.server_url}/projects/{project_key}/repos/{slug}/browse"

            # Default branch
            default_branch = "main"
            if "defaultBranch" in repo_data:
                # Can be "refs/heads/master" format
                branch = repo_data["defaultBranch"]
                if isinstance(branch, str):
                    default_branch = branch.replace("refs/heads/", "")
                elif isinstance(branch, dict):
                    default_branch = branch.get("displayId", "main")

            yield BitbucketServerRepo(
                name=slug,
                full_name=full_name,
                url=web_url,
                clone_url=clone_url,
                visibility=visibility,
                is_archived=is_archived,
                default_branch=default_branch,
            )

    def validate_project_access(self, project_key: str) -> bool:
        """Check if we have access to the project.

        Args:
            project_key: Project key.

        Returns:
            True if accessible.
        """
        try:
            url = f"{self.base_url}/projects/{quote(project_key)}/repos"
            self._request(url, params={"limit": 1})
            return True
        except BitbucketServerAPIError:
            return False
