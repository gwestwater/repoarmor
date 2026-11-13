"""Azure DevOps API client for fetching project repositories."""

import os
from dataclasses import dataclass
from typing import Iterator
from urllib.parse import quote

import requests


@dataclass
class AzureDevOpsRepo:
    """Represents an Azure DevOps repository."""
    name: str
    full_name: str  # org/project/repo
    url: str  # web URL
    clone_url: str  # HTTPS clone URL
    visibility: str  # public, private
    disabled: bool
    default_branch: str


class AzureDevOpsAPIError(Exception):
    """Error from Azure DevOps API."""
    pass


class AzureDevOpsClient:
    """Client for Azure DevOps REST API operations.

    Supports scanning all repositories within an organization/project.

    Args:
        token: Azure DevOps Personal Access Token (PAT).
            If not provided, uses AZURE_DEVOPS_TOKEN environment variable.
            PAT needs 'Code (Read)' scope.
    """

    BASE_URL = "https://dev.azure.com"
    API_VERSION = "7.0"

    def __init__(self, token: str | None = None):
        self.token = token or os.environ.get("AZURE_DEVOPS_TOKEN")
        if not self.token:
            raise AzureDevOpsAPIError(
                "Azure DevOps token required. Set AZURE_DEVOPS_TOKEN environment variable "
                "or provide --token option.\n"
                "Create a PAT at: https://dev.azure.com/{org}/_usersSettings/tokens\n"
                "Required scope: Code (Read)"
            )

    def _get_headers(self) -> dict:
        """Get headers for API requests."""
        import base64
        # Azure DevOps uses Basic auth with PAT (empty username, token as password)
        encoded = base64.b64encode(f":{self.token}".encode()).decode()
        return {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
        }

    def _request(self, url: str, **kwargs) -> dict:
        """Make an API request."""
        response = requests.get(
            url,
            headers=self._get_headers(),
            **kwargs,
        )

        if response.status_code == 401:
            raise AzureDevOpsAPIError(
                "Invalid Azure DevOps token or token lacks required permissions."
            )
        elif response.status_code == 403:
            raise AzureDevOpsAPIError(
                "Access forbidden. Check PAT permissions (needs 'Code (Read)' scope)."
            )
        elif response.status_code == 404:
            raise AzureDevOpsAPIError(
                "Organization or project not found. Check the org/project names."
            )
        elif not response.ok:
            raise AzureDevOpsAPIError(
                f"Azure DevOps API error: HTTP {response.status_code}"
            )

        return response.json()

    def _parse_org_project(self, org_project: str) -> tuple[str, str | None]:
        """Parse 'org/project' or 'org' format.

        Args:
            org_project: Organization name, or 'org/project' format.

        Returns:
            Tuple of (org, project) where project may be None.
        """
        parts = [p.strip() for p in org_project.split("/") if p.strip()]
        if len(parts) == 2:
            return parts[0], parts[1]
        elif len(parts) == 1:
            return parts[0], None
        else:
            raise AzureDevOpsAPIError(
                f"Invalid org/project format: {org_project}\n"
                "Expected: 'org' or 'org/project'"
            )

    def get_projects(self, org: str) -> list[dict]:
        """List all projects in an organization.

        Args:
            org: Organization name.

        Returns:
            List of project data dictionaries.
        """
        url = f"{self.BASE_URL}/{quote(org)}/_apis/projects"
        params = {"api-version": self.API_VERSION, "$top": 500}
        data = self._request(url, params=params)
        return data.get("value", [])

    def get_repos(
        self,
        org: str,
        project: str,
        include_disabled: bool = False,
    ) -> Iterator[AzureDevOpsRepo]:
        """Fetch all repositories for a project.

        Args:
            org: Organization name.
            project: Project name.
            include_disabled: Include disabled repositories.

        Yields:
            AzureDevOpsRepo objects.
        """
        url = (
            f"{self.BASE_URL}/{quote(org)}/{quote(project)}"
            f"/_apis/git/repositories"
        )
        params = {"api-version": self.API_VERSION}
        data = self._request(url, params=params)

        for repo_data in data.get("value", []):
            is_disabled = repo_data.get("isDisabled", False)
            if is_disabled and not include_disabled:
                continue

            # Azure DevOps project visibility
            project_info = repo_data.get("project", {})
            visibility = project_info.get("visibility", "private")

            # Build web URL
            web_url = (
                f"https://dev.azure.com/{quote(org)}/{quote(project)}"
                f"/_git/{quote(repo_data['name'])}"
            )

            # Clone URL
            clone_url = repo_data.get("remoteUrl", web_url)

            default_branch = repo_data.get("defaultBranch", "refs/heads/main")
            # Strip refs/heads/ prefix
            if default_branch.startswith("refs/heads/"):
                default_branch = default_branch[len("refs/heads/"):]

            yield AzureDevOpsRepo(
                name=repo_data["name"],
                full_name=f"{org}/{project}/{repo_data['name']}",
                url=web_url,
                clone_url=clone_url,
                visibility=visibility,
                disabled=is_disabled,
                default_branch=default_branch,
            )

    def get_org_repos(
        self,
        org_project: str,
        include_private: bool = True,
        include_disabled: bool = False,
    ) -> Iterator[AzureDevOpsRepo]:
        """Fetch repositories for an org/project or all projects in an org.

        If org_project is 'org/project', fetches repos for that project.
        If org_project is just 'org', fetches repos across all projects.

        Args:
            org_project: 'org' or 'org/project' format.
            include_private: Include private repositories.
            include_disabled: Include disabled repositories.

        Yields:
            AzureDevOpsRepo objects.
        """
        org, project = self._parse_org_project(org_project)

        if project:
            # Scan a single project
            yield from self.get_repos(org, project, include_disabled=include_disabled)
        else:
            # Scan all projects in the org
            projects = self.get_projects(org)
            for proj in projects:
                proj_name = proj["name"]
                try:
                    for repo in self.get_repos(
                        org, proj_name, include_disabled=include_disabled
                    ):
                        if not include_private and repo.visibility == "private":
                            continue
                        yield repo
                except AzureDevOpsAPIError:
                    # Skip projects we can't access
                    continue

    def validate_org_access(self, org_project: str) -> bool:
        """Check if the token has access to the organization/project.

        Args:
            org_project: 'org' or 'org/project' format.

        Returns:
            True if accessible.
        """
        org, project = self._parse_org_project(org_project)
        try:
            if project:
                url = (
                    f"{self.BASE_URL}/{quote(org)}/{quote(project)}"
                    f"/_apis/git/repositories"
                )
                params = {"api-version": self.API_VERSION, "$top": 1}
                self._request(url, params=params)
            else:
                url = f"{self.BASE_URL}/{quote(org)}/_apis/projects"
                params = {"api-version": self.API_VERSION, "$top": 1}
                self._request(url, params=params)
            return True
        except AzureDevOpsAPIError:
            return False
