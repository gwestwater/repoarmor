"""Bitbucket Cloud API client for fetching workspace repositories."""

import os
from dataclasses import dataclass
from typing import Iterator
from urllib.parse import quote

import requests


@dataclass
class BitbucketRepo:
    """Represents a Bitbucket repository."""
    name: str
    full_name: str  # workspace/repo (slug)
    url: str  # web URL
    clone_url: str  # HTTPS clone URL
    visibility: str  # public, private
    is_archived: bool
    default_branch: str


class BitbucketAPIError(Exception):
    """Error from Bitbucket API."""
    pass


class BitbucketClient:
    """Client for Bitbucket Cloud REST API (2.0) operations.

    Supports scanning all repositories within a workspace.

    Auth options (in order of precedence):
        1. Explicit token parameter
        2. BITBUCKET_APP_PASSWORD env var (+ BITBUCKET_USERNAME)
        3. BITBUCKET_TOKEN env var (repository/workspace access token)

    For App Passwords, create at:
        https://bitbucket.org/account/settings/app-passwords/
    Required permissions: Repositories (Read)
    """

    BASE_URL = "https://api.bitbucket.org/2.0"

    def __init__(self, token: str | None = None, username: str | None = None):
        self.app_password = token or os.environ.get("BITBUCKET_APP_PASSWORD")
        self.username = username or os.environ.get("BITBUCKET_USERNAME")
        self.access_token = os.environ.get("BITBUCKET_TOKEN")

        if self.app_password and self.username:
            self.auth_mode = "basic"
        elif self.app_password and not self.username:
            # If token provided without username, treat as access token
            self.auth_mode = "bearer"
            self.access_token = self.app_password
        elif self.access_token:
            self.auth_mode = "bearer"
        else:
            raise BitbucketAPIError(
                "Bitbucket authentication required. Choose one:\n"
                "  1. Set BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD env vars\n"
                "     (Create app password at: https://bitbucket.org/account/settings/app-passwords/)\n"
                "  2. Set BITBUCKET_TOKEN env var (workspace/repository access token)\n"
                "  3. Use --token with BITBUCKET_USERNAME env var\n"
                "Required permissions: Repositories (Read)"
            )

    def _get_auth(self) -> dict:
        """Get auth kwargs for requests."""
        if self.auth_mode == "basic":
            return {"auth": (self.username, self.app_password)}
        else:
            return {"headers": {"Authorization": f"Bearer {self.access_token}"}}

    def _request(self, url: str, **kwargs) -> dict:
        """Make an API request."""
        auth_kwargs = self._get_auth()
        # Merge headers if both exist
        if "headers" in auth_kwargs and "headers" in kwargs:
            kwargs["headers"].update(auth_kwargs["headers"])
        else:
            kwargs.update(auth_kwargs)

        response = requests.get(url, **kwargs)

        if response.status_code == 401:
            raise BitbucketAPIError(
                "Invalid Bitbucket credentials. Check your app password or access token."
            )
        elif response.status_code == 403:
            raise BitbucketAPIError(
                "Access forbidden. Check that your app password has 'Repositories (Read)' permission."
            )
        elif response.status_code == 404:
            raise BitbucketAPIError(
                "Workspace not found. Check the workspace name/slug."
            )
        elif not response.ok:
            raise BitbucketAPIError(
                f"Bitbucket API error: HTTP {response.status_code}"
            )

        return response.json()

    def _paginate(self, url: str, **kwargs) -> Iterator[dict]:
        """Handle Bitbucket's paginated responses.

        Bitbucket uses cursor-based pagination with a 'next' URL.
        """
        while url:
            data = self._request(url, **kwargs)
            yield from data.get("values", [])
            url = data.get("next")

    def get_workspace_repos(
        self,
        workspace: str,
        include_private: bool = True,
        include_archived: bool = False,
    ) -> Iterator[BitbucketRepo]:
        """Fetch all repositories for a workspace.

        Args:
            workspace: Bitbucket workspace slug or UUID.
            include_private: Include private repositories.
            include_archived: Include archived repositories.

        Yields:
            BitbucketRepo objects.
        """
        url = f"{self.BASE_URL}/repositories/{quote(workspace)}"
        params = {"pagelen": 100}

        if not include_private:
            # Bitbucket supports q parameter for filtering
            params["q"] = 'is_private = false'

        for repo_data in self._paginate(url, params=params):
            # Skip archived/readonly repos if not requested
            # Bitbucket marks archived repos with status "archived" or has_issues=false
            # The most reliable check is the "status" field if available
            is_archived = repo_data.get("status", "active") != "active"
            if is_archived and not include_archived:
                continue

            # Visibility
            is_private = repo_data.get("is_private", True)
            visibility = "private" if is_private else "public"

            # Extract HTTPS clone URL
            clone_url = ""
            for link in repo_data.get("links", {}).get("clone", []):
                if link.get("name") == "https":
                    clone_url = link["href"]
                    break

            # Web URL
            web_url = repo_data.get("links", {}).get("html", {}).get("href", "")

            # Full name is workspace/repo-slug
            full_name = repo_data.get("full_name", f"{workspace}/{repo_data['slug']}")

            # Default branch
            mainbranch = repo_data.get("mainbranch", {})
            default_branch = mainbranch.get("name", "main") if mainbranch else "main"

            yield BitbucketRepo(
                name=repo_data.get("slug", repo_data.get("name", "")),
                full_name=full_name,
                url=web_url,
                clone_url=clone_url,
                visibility=visibility,
                is_archived=is_archived,
                default_branch=default_branch,
            )

    def validate_workspace_access(self, workspace: str) -> bool:
        """Check if we have access to the workspace.

        Args:
            workspace: Workspace slug.

        Returns:
            True if accessible.
        """
        try:
            url = f"{self.BASE_URL}/repositories/{quote(workspace)}"
            self._request(url, params={"pagelen": 1})
            return True
        except BitbucketAPIError:
            return False
