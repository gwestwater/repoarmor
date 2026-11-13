"""CLI commands for RepoArmor."""

import fnmatch
import json
import logging
import os
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlsplit, urlunsplit

import typer
from rich.markup import escape
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from ..config.settings import (
    get_settings, save_config, get_default_config, get_config_path, reload_settings
)
from ..db.database import init_database, session_scope, _commit_with_retry
from ..db import queries
from ..db.models import Finding, ScanHistory
from ..scanner.trufflehog import (
    scan_repository, scan_docker_image, get_repo_name_from_url, check_trufflehog_installed,
    TruffleHogNotFoundError, TruffleHogError
)
from ..scanner.github_api import GitHubClient, GitHubAPIError
from ..scanner.pipeline_check import (
    check_repo_for_trufflehog, PipelineCheckResult, search_repo_workflows, WorkflowSearchResult
)
from ..scanner.member_identity import classify_member
from ..scanner.azure_devops_api import AzureDevOpsClient, AzureDevOpsAPIError
from ..scanner.bitbucket_api import BitbucketClient, BitbucketAPIError
from ..scanner.bitbucket_server_api import BitbucketServerClient, BitbucketServerAPIError
from ..ui.console import console, print_error, print_success, print_warning, print_info
from ..ui.tables import (
    render_repositories_table, render_findings_table, render_finding_detail,
    render_stats_dashboard, render_pipeline_check_table, render_workflow_search_table,
    render_member_check_table
)
from .validators import validate_repo_url, validate_batch_file

logger = logging.getLogger(__name__)

# Create the app
app = typer.Typer(
    name="repoarmor",
    help="A CLI tool for managing TruffleHog secret scanning results",
    no_args_is_help=False,
    invoke_without_command=True,
)

# Config subcommand
config_app = typer.Typer(help="Configuration management")
app.add_typer(config_app, name="config")

# List subcommand group
list_app = typer.Typer(invoke_without_command=True, help="List resources")
app.add_typer(list_app, name="list")

# DB subcommand group
db_app = typer.Typer(help="Database management")
app.add_typer(db_app, name="db")


@app.callback()
def main_callback(ctx: typer.Context) -> None:
    """RepoArmor - GitHub secret detection and management tool."""
    # If no command is invoked, run interactive mode
    if ctx.invoked_subcommand is None:
        # Defer to avoid forward reference - the function is defined later
        ctx.invoke(interactive_mode, mode=None)


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def ensure_trufflehog() -> bool:
    """Ensure TruffleHog is installed."""
    settings = get_settings()
    try:
        version = check_trufflehog_installed(settings.scanner.trufflehog_path)
        logger.debug(f"TruffleHog found: {version}")
        return True
    except TruffleHogNotFoundError as e:
        print_error(str(e))
        return False


def _url_has_auth(url: str) -> bool:
    """Check if URL already contains full authentication credentials (user:pass)."""
    if "://" not in url:
        return False
    after_scheme = url.split("://", 1)[1]
    host_part = after_scheme.split("/")[0]
    # Must have both user:pass (not just user@)
    return "@" in host_part and ":" in host_part.split("@")[0]


def _strip_url_username(url: str) -> str:
    """Strip bare username (without password) from URL.

    Handles URLs like https://orgname@dev.azure.com/... → https://dev.azure.com/...
    """
    if "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    host_part = rest.split("/", 1)
    if "@" in host_part[0] and ":" not in host_part[0].split("@")[0]:
        # Has username@ but no password — strip it
        rest = host_part[0].split("@", 1)[1]
        if len(host_part) > 1:
            rest += "/" + host_part[1]
    return f"{scheme}://{rest}"


def _inject_url_auth(url: str, username: str, password: str) -> str:
    """Inject URL-encoded basic auth credentials into a URL."""
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return url
    if parsed.username is not None and parsed.password is not None:
        return url

    host = parsed.hostname
    if not host:
        return url

    # Preserve explicit port if present
    netloc_host = host if parsed.port is None else f"{host}:{parsed.port}"
    encoded_user = quote(username, safe="")
    encoded_password = quote(password, safe="")
    netloc = f"{encoded_user}:{encoded_password}@{netloc_host}"

    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def _inject_auth_token(url: str, token: str | None = None) -> str:
    """Inject authentication token into a repository URL if needed.

    Supports GitHub PAT, Azure DevOps PAT, and Bitbucket App Password.

    Args:
        url: Repository URL.
        token: Explicit token from --token flag (overrides env vars).

    Returns:
        URL with auth credentials injected, or original URL if not needed.
    """
    if _url_has_auth(url):
        return url

    # Parse URL to inspect scheme/host/path safely
    parsed = urlsplit(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""

    # Local filesystem path - no auth needed
    # Detected by empty host: absolute paths (no scheme) or file:// URLs
    if not host:
        return url

    # GitHub: github.com
    if host == "github.com":
        github_token = token or os.environ.get("GITHUB_TOKEN")
        if github_token:
            return _inject_url_auth(url, "x-access-token", github_token)

    # Azure DevOps: dev.azure.com or *.visualstudio.com
    # API may return URLs with bare username (https://orgname@dev.azure.com/...) - strip it first
    if host == "dev.azure.com" or host.endswith(".visualstudio.com"):
        azure_token = token or os.environ.get("AZURE_DEVOPS_TOKEN")
        if azure_token:
            clean_url = _strip_url_username(url)
            return _inject_url_auth(clean_url, "pat", azure_token)

    # Bitbucket Cloud: bitbucket.org
    if host == "bitbucket.org":
        bb_token = token or os.environ.get("BITBUCKET_APP_PASSWORD")
        bb_user = os.environ.get("BITBUCKET_USERNAME", "x-token-auth")
        if bb_token:
            return _inject_url_auth(url, bb_user, bb_token)

    # Bitbucket Server (self-hosted): any host with /scm/ path that isn't a known cloud host
    if (
        path.startswith("/scm/")
        and host not in ("bitbucket.org", "github.com", "dev.azure.com")
        and not host.endswith(".visualstudio.com")
    ):
        bb_server_token = token or os.environ.get("BITBUCKET_SERVER_TOKEN")
        if bb_server_token:
            bb_server_user = os.environ.get("BITBUCKET_SERVER_USERNAME", "pat")
            return _inject_url_auth(url, bb_server_user, bb_server_token)

    return url


def _resolve_github_visibility(url: str, token: str | None) -> str | None:
    """Look up a GitHub repo's actual visibility via the API.

    Returns None when a GitHub repo can't be resolved so scans can preserve
    any visibility already stored for that repo.
    """
    parsed = urlsplit(url)
    if (parsed.hostname or "").lower() != "github.com":
        return "public"

    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]

    try:
        github = GitHubClient(token=token, require_token=False)
        data = github.get_repo_info(owner, repo)
    except Exception:
        return None

    if not data:
        return None
    visibility = data.get("visibility")
    if not visibility:
        visibility = "private" if data.get("private") else "public"
    return visibility


def _get_head_secret_hashes(repo_url: str, token: str | None = None) -> set[str]:
    """Re-scan a repo at HEAD only (depth=1) and return the set of secret hashes found.

    Used by --current-only to determine which secrets are still in the current code.
    """
    from ..config.settings import get_settings
    settings = get_settings()

    # Inject auth token for the scan
    scan_url = _inject_auth_token(repo_url, token)

    hashes = set()
    try:
        for result in scan_repository(
            scan_url,
            depth=1,
            only_verified=False,
            settings=settings,
        ):
            hashes.add(result.secret_hash)
    except (TruffleHogError, Exception) as e:
        logger.warning(f"HEAD-only scan failed for {repo_url}: {e}")

    return hashes


def _filter_current_only(findings: list, token: str | None = None) -> list:
    """Filter findings to only those whose secret_hash exists at HEAD.

    Groups findings by repo, re-scans each repo at depth=1, and keeps
    only findings whose secret_hash appears in the HEAD scan.
    """
    from collections import defaultdict

    if not findings:
        return findings

    # Group findings by repo URL
    repo_findings: dict[str, list] = defaultdict(list)
    for f in findings:
        repo_url = f.repository.url if f.repository else None
        if repo_url:
            repo_findings[repo_url].append(f)

    # Re-scan each repo at HEAD and collect hashes
    all_head_hashes: set[str] = set()
    total_repos = len(repo_findings)

    console.print(f"\n[info]Checking {total_repos} repositories for secrets in current code (HEAD only)...[/info]")

    for i, repo_url in enumerate(repo_findings.keys(), 1):
        repo_name = get_repo_name_from_url(repo_url)
        console.print(f"  [{i}/{total_repos}] Scanning HEAD of {repo_name}...")
        head_hashes = _get_head_secret_hashes(repo_url, token)
        all_head_hashes.update(head_hashes)

    # Filter findings
    filtered = [f for f in findings if f.secret_hash in all_head_hashes]

    console.print(f"  Found {len(filtered)} of {len(findings)} secrets still in current code\n")

    return filtered


def _fetch_github_org_repos(
    org: str,
    token: str | None,
    include_private: bool,
    include_archived: bool,
) -> list[tuple[str, str, str]]:
    """Fetch repos from a GitHub organization and return (scan_url, storage_url, visibility) tuples."""
    github = GitHubClient(token=token)

    if not github.validate_org_access(org):
        raise GitHubAPIError(f"Cannot access organization: {org}. Check the org name and token permissions.")

    repos = list(github.get_org_repos(
        org,
        include_private=include_private,
        include_archived=include_archived,
    ))

    github_token = token or os.environ.get("GITHUB_TOKEN")
    urls_to_scan = []
    for repo in repos:
        if repo.visibility != "public" and github_token:
            auth_url = repo.clone_url.replace(
                "https://github.com/",
                f"https://x-access-token:{github_token}@github.com/"
            )
            urls_to_scan.append((auth_url, repo.url, repo.visibility))
        else:
            urls_to_scan.append((repo.clone_url, repo.url, repo.visibility))

    return urls_to_scan


def _fetch_github_user_repos(
    username: str,
    token: str | None,
    include_archived: bool,
) -> list[tuple[str, str, str]]:
    """Fetch a user's public repos and return (scan_url, storage_url, visibility) tuples.

    A token is optional here (used only to raise rate limits); listing a user's
    repositories via /users/{username}/repos only ever returns public repos.
    """
    github = GitHubClient(token=token, require_token=False)

    repos = list(github.get_user_repos(
        username=username,
        include_private=False,
        include_archived=include_archived,
    ))

    urls_to_scan = []
    for repo in repos:
        urls_to_scan.append((repo.clone_url, repo.url, repo.visibility))

    return urls_to_scan


def _fetch_github_org_member_repos(
    org: str,
    token: str | None,
    include_archived: bool,
) -> list[tuple[str, str, str]]:
    """List all org members then aggregate each member's public repos (Step #2)."""
    github = GitHubClient(token=token, require_token=False)

    members_iter, public_only_used = github.get_org_members(org)
    members = list(members_iter)
    if not members:
        raise GitHubAPIError(f"No members found in org '{org}'. Check the org name and token permissions.")

    if public_only_used:
        console.print(f"[yellow]Warning: showing only public members of '{org}' (token not an org member)[/yellow]")
    console.print(f"[dim]Found {len(members)} members in org '{org}'[/dim]")

    urls_to_scan: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for username in members:
        for item in _fetch_github_user_repos(username, token, include_archived):
            if item[1] not in seen:
                seen.add(item[1])
                urls_to_scan.append(item)

    return urls_to_scan


def _fetch_github_multi_org_member_repos(
    orgs: list[str],
    token: str | None,
    include_archived: bool,
) -> list[tuple[str, str, str]]:
    """Collect members from multiple orgs, deduplicate users, then scan each user's public repos (Step #3)."""
    github = GitHubClient(token=token, require_token=False)

    # Deduplicate users across orgs
    seen_users: set[str] = set()
    for org in orgs:
        members_iter, public_only_used = github.get_org_members(org)
        members = list(members_iter)
        if public_only_used:
            console.print(f"[yellow]Warning: only public members visible for '{org}' (token not an org member)[/yellow]")
        console.print(f"[dim]Found {len(members)} members in org '{org}'[/dim]")
        seen_users.update(members)

    unique_users = sorted(seen_users)
    console.print(f"[dim]{len(unique_users)} unique users across {len(orgs)} org(s)[/dim]")

    # Collect each user's public repos, deduplicating by URL
    urls_to_scan: list[tuple[str, str, str]] = []
    seen_repos: set[str] = set()
    for username in unique_users:
        for item in _fetch_github_user_repos(username, token, include_archived):
            if item[1] not in seen_repos:
                seen_repos.add(item[1])
                urls_to_scan.append(item)

    return urls_to_scan


def _fetch_azure_org_repos(
    org_project: str,
    token: str | None,
    include_private: bool,
    include_archived: bool,
) -> list[tuple[str, str, str]]:
    """Fetch repos from Azure DevOps org/project and return (scan_url, storage_url, visibility) tuples."""
    client = AzureDevOpsClient(token=token)

    if not client.validate_org_access(org_project):
        raise AzureDevOpsAPIError(
            f"Cannot access Azure DevOps: {org_project}. Check the org/project name and token permissions."
        )

    repos = list(client.get_org_repos(
        org_project,
        include_private=include_private,
        include_disabled=include_archived,
    ))

    azure_token = token or os.environ.get("AZURE_DEVOPS_TOKEN")
    urls_to_scan = []
    for repo in repos:
        scan_url = repo.clone_url
        if azure_token and not _url_has_auth(scan_url):
            scan_url = _inject_url_auth(_strip_url_username(scan_url), "pat", azure_token)
        urls_to_scan.append((scan_url, repo.url, repo.visibility))

    return urls_to_scan


def _fetch_bitbucket_workspace_repos(
    workspace: str,
    token: str | None,
    include_private: bool,
    include_archived: bool,
) -> list[tuple[str, str, str]]:
    """Fetch repos from Bitbucket workspace and return (scan_url, storage_url, visibility) tuples."""
    client = BitbucketClient(token=token)

    if not client.validate_workspace_access(workspace):
        raise BitbucketAPIError(
            f"Cannot access Bitbucket workspace: {workspace}. Check the workspace name and credentials."
        )

    repos = list(client.get_workspace_repos(
        workspace,
        include_private=include_private,
        include_archived=include_archived,
    ))

    urls_to_scan = []
    for repo in repos:
        scan_url = repo.clone_url
        # Inject auth into clone URL
        scan_url = _inject_auth_token(scan_url, token)
        urls_to_scan.append((scan_url, repo.url, repo.visibility))

    return urls_to_scan


def _fetch_bitbucket_server_project_repos(
    server_url: str,
    project_key: str,
    token: str | None,
    include_private: bool,
    include_archived: bool,
) -> list[tuple[str, str, str]]:
    """Fetch repos from Bitbucket Server project and return (scan_url, storage_url, visibility) tuples."""
    client = BitbucketServerClient(server_url=server_url, token=token)

    if not client.validate_project_access(project_key):
        raise BitbucketServerAPIError(
            f"Cannot access Bitbucket Server project: {project_key} on {server_url}. "
            "Check the project key and credentials."
        )

    repos = list(client.get_project_repos(
        project_key,
        include_private=include_private,
        include_archived=include_archived,
    ))

    urls_to_scan = []
    for repo in repos:
        scan_url = repo.clone_url
        # Inject auth into clone URL
        scan_url = _inject_auth_token(scan_url, token)
        urls_to_scan.append((scan_url, repo.url, repo.visibility))

    return urls_to_scan


# Scan commands

@app.command("secret-scan")
def scan(
    repo_urls: Optional[list[str]] = typer.Argument(None, help="Repository URL(s) to scan (GitHub, Azure DevOps, or Bitbucket)"),
    batch: Optional[Path] = typer.Option(None, "--batch", "-b", help="File containing repository URLs to scan"),
    org: Optional[str] = typer.Option(None, "--org", "-o", help="GitHub organization to scan all repos"),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="GitHub user to scan all public repos"),
    user_org: Optional[str] = typer.Option(None, "--user-org", help="GitHub org — scan public repos of all its members"),
    user_orgs: Optional[list[str]] = typer.Option(None, "--user-orgs", help="GitHub org to include (repeat for multiple: --user-orgs org1 --user-orgs org2)"),
    azure_org: Optional[str] = typer.Option(None, "--azure-org", help="Azure DevOps org/project to scan (e.g., myorg/myproject)"),
    bb_workspace: Optional[str] = typer.Option(None, "--bb-workspace", help="Bitbucket Cloud workspace to scan all repos"),
    bb_server_project: Optional[str] = typer.Option(None, "--bb-server-project", help="Bitbucket Server project key to scan all repos (e.g., PLATFORM)"),
    bb_server_url: Optional[str] = typer.Option(None, "--bb-server-url", help="Bitbucket Server base URL (e.g., https://code.example.com)"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="Access token (GitHub PAT, Azure DevOps PAT, or Bitbucket App Password)"),
    include_archived: bool = typer.Option(False, "--include-archived", help="Include archived/disabled repos when scanning org"),
    include_private: bool = typer.Option(True, "--include-private/--public-only", help="Include private repos when scanning org"),
    depth: Optional[int] = typer.Option(None, "--depth", "-d", help="Number of commits to scan"),
    branch: Optional[str] = typer.Option(None, "--branch", help="Specific branch to scan"),
    only_verified: bool = typer.Option(False, "--only-verified", help="Only include findings verified by TruffleHog"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Scan repositories for secrets (GitHub, Azure DevOps, or Bitbucket).

    Accepts one or more repository URLs as arguments.

    Examples:
        repoarmor secret-scan https://github.com/owner/repo
        repoarmor secret-scan URL1 URL2 URL3
        repoarmor secret-scan https://dev.azure.com/org/project/_git/repo
        repoarmor secret-scan https://bitbucket.org/owner/repo
        repoarmor secret-scan --org mycompany
        repoarmor secret-scan --user alice
        repoarmor secret-scan --user-org mycompany
        repoarmor secret-scan --user-orgs org1 --user-orgs org2 --user-orgs org3
        repoarmor secret-scan --azure-org myorg/myproject
        repoarmor secret-scan --bb-workspace myworkspace
        repoarmor secret-scan --bb-server-project PLATFORM --bb-server-url https://code.example.com
        repoarmor secret-scan --batch repos.txt
    """
    setup_logging(verbose)

    if not ensure_trufflehog():
        raise typer.Exit(1)

    settings = get_settings()
    init_database(settings.database.path)

    # Normalize repo_urls: typer gives None or a list
    repo_url_list: list[str] = repo_urls if repo_urls else []

    # Support shorthand formats and auto-detect org vs repo (only for single URL)
    if len(repo_url_list) == 1 and not org and not user and not user_org and not user_orgs and not azure_org and not bb_workspace and not bb_server_project and not batch:
        clean_url = repo_url_list[0].rstrip("/")

        # Handle shorthand: "owner/repo" or "orgname" (without full URL)
        # Skip local filesystem paths (absolute, relative, home-relative, Windows drive/UNC, file://,
        # or a bare relative name/path that happens to exist as a git repo on disk, e.g. "myrepo" or "parent/myrepo")
        expanded_path = Path(clean_url).expanduser()
        has_windows_drive = len(clean_url) >= 2 and clean_url[1] == ":" and clean_url[0].isalpha()
        is_unc_path = clean_url.startswith("\\\\")
        is_existing_local_repo = (expanded_path / ".git").exists()
        is_local_path = (
            clean_url.startswith("file://")
            or clean_url.startswith("./")
            or clean_url.startswith("../")
            or clean_url.startswith("~")
            or expanded_path.is_absolute()
            or has_windows_drive
            or is_unc_path
            or is_existing_local_repo
        )
        if not is_local_path and not clean_url.startswith("http://") and not clean_url.startswith("https://") and not clean_url.startswith("git@"):
            parts = [p for p in clean_url.split("/") if p]
            if len(parts) == 2:
                # Shorthand repo: "owner/repo" -> "https://github.com/owner/repo"
                repo_url_list = [f"https://github.com/{clean_url}"]
                print_info(f"Expanded to: {repo_url_list[0]}")
            elif len(parts) == 1:
                # Shorthand org: "orgname" -> scan org
                org = parts[0]
                repo_url_list = []
                print_info(f"Detected organization, scanning all repos in: {org}")
        else:
            # Full URL provided - check if it's a GitHub org URL
            if "github.com/" in clean_url:
                path_part = clean_url.split("github.com/", 1)[1]
                path_parts = [p for p in path_part.split("/") if p]
                if len(path_parts) == 1:
                    # This is an org URL: https://github.com/orgname
                    org = path_parts[0]
                    repo_url_list = []
                    print_info(f"Detected organization URL, scanning all repos in: {org}")

    # Determine URLs to scan: (scan_url, storage_url, visibility)
    urls_to_scan: list[tuple[str, str, str | None]] = []

    # Validate bb-server-project requires bb-server-url
    if bb_server_project and not bb_server_url:
        print_error("--bb-server-project requires --bb-server-url (e.g., --bb-server-url https://code.example.com)")
        raise typer.Exit(1)

    # Determine which org-level scan to run (if any)
    org_target = org or user or user_org or (user_orgs and ",".join(user_orgs)) or azure_org or bb_workspace or bb_server_project

    if org_target:
        if org:
            provider_name = "GitHub"
        elif user:
            provider_name = "GitHub user"
        elif user_org:
            provider_name = "GitHub org members"
        elif user_orgs:
            provider_name = "GitHub multi-org members"
        elif azure_org:
            provider_name = "Azure DevOps"
        elif bb_server_project:
            provider_name = "Bitbucket Server"
        else:
            provider_name = "Bitbucket"

        console.print(f"\n[header]Fetching repositories from {provider_name}:[/header] [repo]{org_target}[/repo]")

        try:
            if org:
                urls_to_scan = _fetch_github_org_repos(org, token, include_private, include_archived)
            elif user:
                urls_to_scan = _fetch_github_user_repos(user, token, include_archived)
            elif user_org:
                urls_to_scan = _fetch_github_org_member_repos(user_org, token, include_archived)
            elif user_orgs:
                if not user_orgs:
                    print_error("--user-orgs requires at least one org slug.")
                    raise typer.Exit(1)
                # Flatten comma-separated values and strip whitespace to support both styles
                org_list = [o.strip() for v in user_orgs for o in v.split(",") if o.strip()]
                urls_to_scan = _fetch_github_multi_org_member_repos(org_list, token, include_archived)
            elif azure_org:
                urls_to_scan = _fetch_azure_org_repos(azure_org, token, include_private, include_archived)
            elif bb_server_project:
                urls_to_scan = _fetch_bitbucket_server_project_repos(bb_server_url, bb_server_project, token, include_private, include_archived)
            elif bb_workspace:
                urls_to_scan = _fetch_bitbucket_workspace_repos(bb_workspace, token, include_private, include_archived)

            if not urls_to_scan:
                print_warning(f"No repositories found in: {org_target}")
                raise typer.Exit(0)

            print_info(f"Found {len(urls_to_scan)} repositories to scan")

        except (GitHubAPIError, AzureDevOpsAPIError, BitbucketAPIError, BitbucketServerAPIError) as e:
            print_error(str(e))
            raise typer.Exit(1)

    elif batch:
        try:
            batch_urls = validate_batch_file(str(batch))
            urls_to_scan = [
                (url, url, _resolve_github_visibility(url, token))
                for url in batch_urls
            ]
            print_info(f"Loaded {len(urls_to_scan)} repositories from {batch}")
        except ValueError as e:
            print_error(str(e))
            raise typer.Exit(1)
    elif repo_url_list:
        for url in repo_url_list:
            try:
                validated_url = validate_repo_url(url)
                scan_url = _inject_auth_token(validated_url, token)
                visibility = _resolve_github_visibility(validated_url, token)
                urls_to_scan.append((scan_url, validated_url, visibility))
            except ValueError as e:
                print_error(f"{url}: {e}")
                raise typer.Exit(1)
    else:
        print_error("Please provide repository URL(s), --batch file, or --org")
        raise typer.Exit(1)

    # Determine repo_type for tagging: personal = user/user-org scans, org = --org scans
    if user or user_org or user_orgs:
        scan_repo_type = "personal"
    elif org:
        scan_repo_type = "org"
    else:
        scan_repo_type = "unknown"

    # Helper function to scan a single repo (for parallel execution)
    def scan_single_repo(scan_url: str, storage_url: str, visibility: str | None) -> tuple[int, int, str | None]:
        """Scan a single repository and return (findings_count, new_count, error)."""
        repo_name = get_repo_name_from_url(storage_url)
        findings_count = 0
        new_findings_count = 0
        error_msg = None

        # Step 1: Create/get repo and scan history in a short dedicated transaction.
        # This commits and closes quickly, giving us stable integer IDs that
        # won't be lost by rollbacks during the long-running scan transaction.
        effective_depth = depth if depth is not None else settings.scanner.default_depth
        try:
            with session_scope() as setup_session:
                repo = queries.get_repository_by_url(setup_session, storage_url)
                if not repo:
                    repo = queries.create_repository(
                        setup_session, storage_url, repo_name, visibility or "public", scan_repo_type
                    )
                elif visibility is not None and repo.visibility != visibility:
                    repo.visibility = visibility
                if scan_repo_type != "unknown" and repo.repo_type == "unknown":
                    repo.repo_type = scan_repo_type
                repo_id = repo.id
                scan_config = json.dumps({
                    "depth": effective_depth,
                    "branch": branch,
                    "only_verified": only_verified,
                })
                history = queries.create_scan_history(setup_session, repo_id, scan_config)
                history_id = history.id
            # setup_session commits and closes here - repo_id/history_id are plain ints
        except Exception as e:
            return 0, 0, str(e)

        def mark_scan_failed(message: str) -> None:
            try:
                with session_scope() as cleanup_session:
                    history = cleanup_session.get(ScanHistory, history_id)
                    if history and history.status == "running":
                        queries.complete_scan_history(
                            cleanup_session, history, findings_count, new_findings_count,
                            "failed", message
                        )
            except Exception:
                pass

        # Step 2: Read existing hashes in a short read transaction, then close it.
        try:
            with session_scope() as read_session:
                existing_hashes = {
                    f.secret_hash for f in queries.get_findings_by_repo(read_session, repo_id)
                }
        except Exception as e:
            error_msg = str(e)
            mark_scan_failed(error_msg)
            return 0, 0, error_msg

        # Step 3: Run TruffleHog with no DB connection open — collect new findings in memory.
        new_results = []
        try:
            for result in scan_repository(
                scan_url,
                depth=effective_depth,
                branch=branch,
                only_verified=only_verified,
                settings=settings,
            ):
                findings_count += 1
                if result.secret_hash not in existing_hashes:
                    existing_hashes.add(result.secret_hash)
                    new_results.append(result)
        except TruffleHogError as e:
            error_msg = str(e)

        # Step 4: Write all new findings in one short write transaction.
        try:
            with session_scope() as session:
                for result in new_results:
                    queries.create_finding(
                        session,
                        repo_id=repo_id,
                        detector_type=result.detector_type,
                        decoder_type=result.decoder_type,
                        file_path=result.file_path,
                        line_number=result.line_number,
                        commit=result.commit,
                        author=result.author,
                        author_email=result.author_email,
                        commit_date=result.commit_date,
                        message=result.message,
                        secret_hash=result.secret_hash,
                        redacted_secret=result.redacted_secret,
                        raw_finding=result.raw_finding,
                        verified_by_trufflehog=result.verified_by_trufflehog,
                    )
                    new_findings_count += 1

                repo = queries.get_repository_by_id(session, repo_id)
                if repo:
                    queries.update_repository_stats(session, repo)

                history = session.get(ScanHistory, history_id)
                if history:
                    queries.complete_scan_history(
                        session, history, findings_count, new_findings_count,
                        "failed" if error_msg else "completed", error_msg
                    )
        except Exception as e:
            if not error_msg:
                error_msg = str(e)
            mark_scan_failed(error_msg)

        return findings_count, new_findings_count, error_msg

    # Scan repositories
    total_findings = 0
    total_new_findings = 0
    use_parallel = len(urls_to_scan) > 1 and settings.scanner.parallel_scans > 1

    if use_parallel:
        # Parallel scanning for multiple repos
        console.print(f"\n[info]Scanning {len(urls_to_scan)} repositories in parallel (max {settings.scanner.parallel_scans} concurrent)...[/info]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(urls_to_scan))

            with ThreadPoolExecutor(max_workers=settings.scanner.parallel_scans) as executor:
                futures = {
                    executor.submit(scan_single_repo, scan_url, storage_url, visibility): storage_url
                    for scan_url, storage_url, visibility in urls_to_scan
                }

                for future in as_completed(futures):
                    storage_url = futures[future]
                    repo_name = get_repo_name_from_url(storage_url)

                    try:
                        findings_count, new_count, error = future.result()
                        total_findings += findings_count
                        total_new_findings += new_count

                        if error:
                            progress.console.print(f"  [red]✗[/red] {repo_name}: {error}")
                        elif new_count > 0:
                            progress.console.print(f"  [yellow]![/yellow] {repo_name}: {new_count} new secrets")
                        else:
                            progress.console.print(f"  [green]✓[/green] {repo_name}: clean")

                    except Exception as e:
                        progress.console.print(f"  [red]✗[/red] {repo_name}: {e}")

                    progress.advance(task)
    else:
        # Sequential scanning for single repo or when parallel is disabled
        for scan_url, storage_url, visibility in urls_to_scan:
            repo_name = get_repo_name_from_url(storage_url)
            console.print(f"\n[header]Scanning:[/header] [repo]{repo_name}[/repo]")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning...", total=None)

                findings_count, new_count, error = scan_single_repo(scan_url, storage_url, visibility)
                total_findings += findings_count
                total_new_findings += new_count

                progress.update(task, completed=True, description="Scan complete")

            if error:
                print_error(f"Scan failed: {error}")
            elif new_count > 0:
                print_warning(f"Found {new_count} new secrets ({findings_count} total)")
            else:
                print_success(f"No new secrets found ({findings_count} total in history)")

    # Summary for batch scans
    if len(urls_to_scan) > 1:
        with session_scope() as session:
            db_total = queries.get_total_findings_count(session)
        console.print(f"\n[header]Batch Scan Complete[/header]")
        console.print(f"Repositories scanned: {len(urls_to_scan)}")
        console.print(f"Findings in this scan: {total_findings}")
        console.print(f"New findings: {total_new_findings}")
        console.print(f"Total findings in database: {db_total}")


@app.command("secret-scan-docker")
def scan_docker(
    images: Optional[list[str]] = typer.Option(None, "--image", "-i", help="Docker image to scan (repeat for multiple: --image nginx:latest --image redis:alpine)"),
    image_list: Optional[str] = typer.Option(None, "--images", help="Comma-separated Docker images to scan"),
    only_verified: bool = typer.Option(False, "--only-verified", help="Only include findings verified by TruffleHog"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Scan Docker images for secrets.

    Uses local Docker credentials for private registries (run `docker login` first).

    Examples:
        repoarmor secret-scan-docker --image nginx:latest
        repoarmor secret-scan-docker --image nginx:latest --image redis:alpine
        repoarmor secret-scan-docker --images nginx:latest,redis:alpine
        repoarmor secret-scan-docker --image registry.example.com/myapp:v1
    """
    setup_logging(verbose)

    if not ensure_trufflehog():
        raise typer.Exit(1)

    # Combine --image flags and --images comma-separated values
    all_images: list[str] = []
    if images:
        all_images.extend(images)
    if image_list:
        all_images.extend(i.strip() for i in image_list.split(",") if i.strip())

    if not all_images:
        print_error("Provide at least one image via --image or --images.")
        raise typer.Exit(1)

    settings = get_settings()
    init_database(settings.database.path)

    total_findings = 0
    total_new_findings = 0

    for image in all_images:
        console.print(f"\n[header]Scanning Docker image:[/header] [repo]{image}[/repo]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)
            findings_count = 0
            new_count = 0
            error_msg = None
            history_id = None

            def mark_scan_failed(message: str) -> None:
                if history_id is None:
                    return
                try:
                    with session_scope() as cleanup_session:
                        history = cleanup_session.get(ScanHistory, history_id)
                        if history and history.status == "running":
                            queries.complete_scan_history(
                                cleanup_session, history, findings_count, new_count,
                                "failed", message
                            )
                except Exception:
                    pass

            try:
                with session_scope() as setup_session:
                    repo = queries.get_repository_by_url(setup_session, image)
                    if not repo:
                        repo = queries.create_repository(setup_session, image, image, "public", "docker")
                    else:
                        repo.repo_type = "docker"
                    repo_id = repo.id
                    scan_config = json.dumps({
                        "image": image,
                        "only_verified": only_verified,
                    })
                    history = queries.create_scan_history(setup_session, repo_id, scan_config)
                    history_id = history.id

                # Read existing hashes in a short read transaction.
                with session_scope() as read_session:
                    existing_hashes = {
                        f.secret_hash for f in queries.get_findings_by_repo(read_session, repo_id)
                    }

                # Run TruffleHog without a DB connection open; collect new findings in memory.
                new_results = []
                for result in scan_docker_image(
                    image,
                    only_verified=only_verified,
                    settings=settings,
                ):
                    findings_count += 1
                    if result.secret_hash not in existing_hashes:
                        existing_hashes.add(result.secret_hash)
                        new_results.append(result)

                # Write all new findings in one short write transaction.
                with session_scope() as session:
                    for result in new_results:
                        queries.create_finding(
                            session,
                            repo_id=repo_id,
                            detector_type=result.detector_type,
                            decoder_type=result.decoder_type,
                            file_path=result.file_path,
                            line_number=result.line_number,
                            commit=result.commit,
                            author=result.author,
                            author_email=result.author_email,
                            commit_date=result.commit_date,
                            message=result.message,
                            secret_hash=result.secret_hash,
                            redacted_secret=result.redacted_secret,
                            raw_finding=result.raw_finding,
                            verified_by_trufflehog=result.verified_by_trufflehog,
                        )
                        new_count += 1
                    repo = queries.get_repository_by_id(session, repo_id)
                    if repo:
                        queries.update_repository_stats(session, repo)

                    history = session.get(ScanHistory, history_id)
                    if history:
                        queries.complete_scan_history(
                            session, history, findings_count, new_count,
                            "completed", None
                        )
            except TruffleHogError as e:
                error_msg = str(e)
                mark_scan_failed(error_msg)
            except Exception as e:
                error_msg = str(e)
                mark_scan_failed(error_msg)

            progress.update(task, completed=True, description="Scan complete")

        if error_msg:
            print_error(f"Scan failed: {error_msg}")
        elif new_count > 0:
            print_warning(f"Found {new_count} new secrets ({findings_count} total)")
        else:
            print_success(f"No new secrets found ({findings_count} total in history)")

        total_findings += findings_count
        total_new_findings += new_count

    if len(all_images) > 1:
        console.print(f"\n[header]Docker Scan Complete[/header]")
        console.print(f"Images scanned: {len(all_images)}")
        console.print(f"Total findings: {total_findings}")
        console.print(f"New findings: {total_new_findings}")


@db_app.command("retag-personal")
def db_retag_personal(
    user: Optional[str] = typer.Option(None, "--user", "-u", help="GitHub username whose repos to tag as personal"),
    user_org: Optional[str] = typer.Option(None, "--user-org", help="GitHub org — tag public repos of all its members as personal"),
    user_orgs: Optional[list[str]] = typer.Option(None, "--user-orgs", help="Repeat for multiple orgs (same as secret-scan --user-orgs)"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="GitHub token (reads GITHUB_TOKEN env var if omitted)"),
) -> None:
    """Tag existing repos in the DB as 'personal' without re-scanning.

    Examples:
        repoarmor db retag-personal --user alice
        repoarmor db retag-personal --user-org mycompany
        repoarmor db retag-personal --user-orgs org1 --user-orgs org2
    """
    if not user and not user_org and not user_orgs:
        print_error("Provide --user, --user-org, or --user-orgs.")
        raise typer.Exit(1)

    # Collect the set of GitHub usernames to tag
    usernames: set[str] = set()

    if user:
        usernames.add(user)

    github = GitHubClient(token=token, require_token=False)

    if user_org:
        members_iter, public_only = github.get_org_members(user_org)
        members = list(members_iter)
        if public_only:
            print_warning(f"Only public members visible for '{user_org}'.")
        console.print(f"[dim]Found {len(members)} members in '{user_org}'[/dim]")
        usernames.update(members)

    if user_orgs:
        org_list = [o.strip() for v in user_orgs for o in v.split(",") if o.strip()]
        for org in org_list:
            members_iter, public_only = github.get_org_members(org)
            members = list(members_iter)
            if public_only:
                print_warning(f"Only public members visible for '{org}'.")
            console.print(f"[dim]Found {len(members)} members in '{org}'[/dim]")
            usernames.update(members)

    console.print(f"[dim]Tagging repos for {len(usernames)} unique user(s) as 'personal'...[/dim]")

    settings = get_settings()
    init_database(settings.database.path)

    updated = 0
    with session_scope() as session:
        all_repos = queries.get_all_repositories(session)
        for repo in all_repos:
            owner = repo.name.split("/")[0] if "/" in repo.name else None
            if owner and owner in usernames and repo.repo_type != "personal":
                repo.repo_type = "personal"
                updated += 1

    print_success(f"Tagged {updated} repositories as 'personal'.")


@db_app.command("retag-docker")
def db_retag_docker() -> None:
    """Auto-tag existing repos as 'docker' if their URL looks like a Docker image (not an http URL).

    Example:
        repoarmor db retag-docker
    """
    settings = get_settings()
    init_database(settings.database.path)

    updated = 0
    with session_scope() as session:
        all_repos = queries.get_all_repositories(session)
        for repo in all_repos:
            is_url = repo.url.startswith(("http://", "https://", "file://", "git@"))
            is_local_path = repo.url.startswith("/") or repo.url.startswith("./") or repo.url.startswith("~")
            if not is_url and not is_local_path and repo.repo_type != "docker":
                repo.repo_type = "docker"
                updated += 1

    print_success(f"Tagged {updated} repositories as 'docker'.")


@list_app.callback(invoke_without_command=True)
def list_repos(
    ctx: typer.Context,
    with_stats: bool = typer.Option(False, "--with-stats", "-s", help="Include finding statistics"),
    personal: bool = typer.Option(False, "--personal", help="Show only personal repos (scanned via --user / --user-org)"),
    org_only: bool = typer.Option(False, "--org-only", help="Show only org repos (scanned via --org)"),
    docker: bool = typer.Option(False, "--docker", help="Show only Docker image scans"),
    image: Optional[str] = typer.Option(None, "--image", "-i", help="Filter by exact Docker image name (e.g. nginx:latest)"),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="Filter by GitHub username (owner of the repo)"),
) -> None:
    """List all scanned repositories."""
    if ctx.invoked_subcommand is not None:
        return
    settings = get_settings()
    init_database(settings.database.path)

    repo_type_filter = "personal" if personal else ("org" if org_only else ("docker" if docker else None))
    with session_scope() as session:
        repos = queries.get_all_repositories(session, repo_type=repo_type_filter, owner=user)
        if image:
            repos = [r for r in repos if r.url == image or r.name == image]
        render_repositories_table(repos, with_stats=with_stats)


@list_app.command("org-users")
def list_org_users(
    org: str = typer.Argument(..., help="GitHub organization slug"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="GitHub PAT with read:org scope"),
) -> None:
    """List all members of a GitHub organization."""
    github = GitHubClient(token=token, require_token=False)

    # Verify the slug is a real org using the unauthenticated public endpoint
    try:
        requests.get(f"https://api.github.com/orgs/{org}", timeout=10).raise_for_status()
    except Exception:
        print_error(f"'{org}' is not a GitHub organization or does not exist.")
        raise typer.Exit(1)

    try:
        members_iter, public_only_used = github.get_org_members(org)
        members = list(members_iter)
    except GitHubAPIError as e:
        print_error(str(e))
        print_info(
            "To list ALL org members you must:\n"
            "  1. Be a member of the org on GitHub\n"
            "  2. Use a token with 'read:org' scope (classic PAT) or\n"
            "     'Organization members: read' permission (fine-grained PAT)\n"
            "Without these, only publicly-visible members can be listed."
        )
        raise typer.Exit(1)

    if public_only_used:
        print_warning(f"Not an org member — showing only members who have made their membership public.")
        print_warning("To see all members, use a token from an account that belongs to the org.")

    if not members:
        print_warning(f"No members found in org '{org}'.")
        raise typer.Exit(0)

    table = Table(title=f"Members of {org} ({len(members)})")
    table.add_column("Username", style="cyan")
    for username in sorted(members):
        table.add_row(username)
    console.print(table)


def _parse_github_owner_repo(repo: str, default_org: str | None = None) -> tuple[str, str]:
    """Parse an 'owner/repo' shorthand, a bare 'repo' name (with default_org), or a full GitHub URL."""
    cleaned = repo.strip().rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    if "github.com/" in cleaned:
        cleaned = cleaned.split("github.com/", 1)[1]
    elif cleaned.startswith("git@github.com:"):
        cleaned = cleaned[len("git@github.com:"):]

    parts = [p for p in cleaned.split("/") if p]
    if len(parts) == 2:
        return parts[0], parts[1]
    if len(parts) == 1:
        if default_org:
            return default_org, parts[0]
        raise ValueError(
            f"'{repo}' has no owner. Use 'owner/repo', a full GitHub URL, or pass --org to set a default owner."
        )
    raise ValueError(
        f"Invalid repository reference: {repo}\n"
        "Expected 'owner/repo' or a GitHub URL like https://github.com/owner/repo"
    )


_LARGE_BRANCH_SCAN_THRESHOLD = 300


def _resolve_branches_to_check(
    github: GitHubClient,
    owner: str,
    repo: str,
    branches: list[str],
    branch_patterns: list[str],
    all_branches: bool,
) -> list[str | None]:
    """Resolve which branch(es) of a repo to check, based on --branch/--branch-pattern/--all-branches.

    Returns `[None]` (meaning "just the default branch", no extra API calls) only
    when none of those flags were given. When --branch-pattern or --all-branches
    is given but matches no branches in this specific repo, an empty list is
    returned so the repo is skipped rather than silently falling back to
    checking its default branch (which would misreport a release-branch scan as
    "found"/"missing" based on unrelated default-branch content).
    """
    if not branches and not branch_patterns and not all_branches:
        return [None]

    if all_branches:
        try:
            return sorted(github.list_branches(owner, repo))
        except GitHubAPIError as e:
            print_warning(f"Could not list branches for {owner}/{repo}: {e}")
            return []

    try:
        all_repo_branches = github.list_branches(owner, repo)
    except GitHubAPIError as e:
        print_warning(f"Could not list branches for {owner}/{repo}: {e}")
        return []

    available = set(all_repo_branches)
    resolved_list: list[str] = [
        name for name in dict.fromkeys(branches) if name in available
    ]
    for pattern in branch_patterns:
        for name in all_repo_branches:
            if name not in resolved_list and fnmatch.fnmatch(name, pattern):
                resolved_list.append(name)
    return resolved_list


def _check_repo_across_branches(
    github: GitHubClient,
    owner: str,
    repo: str,
    repo_url: str | None,
    visibility: str | None,
    default_branch: str | None,
    branches: list[str],
    branch_patterns: list[str],
    all_branches: bool,
) -> list[PipelineCheckResult]:
    """Resolve which branch(es) to check for one repo, then check each of them."""
    resolved = _resolve_branches_to_check(github, owner, repo, branches, branch_patterns, all_branches)
    return [
        check_repo_for_trufflehog(github, owner, repo, repo_url, visibility, default_branch, branch=b)
        for b in resolved
    ]


def _search_repo_workflows_across_branches(
    github: GitHubClient,
    owner: str,
    repo: str,
    pattern: str,
    use_regex: bool,
    repo_url: str | None,
    visibility: str | None,
    branches: list[str],
    branch_patterns: list[str],
    all_branches: bool,
) -> list[WorkflowSearchResult]:
    """Resolve which branch(es) to search for one repo, then search each of them."""
    resolved = _resolve_branches_to_check(github, owner, repo, branches, branch_patterns, all_branches)
    return [
        search_repo_workflows(github, owner, repo, pattern, use_regex, repo_url, visibility, branch=b)
        for b in resolved
    ]


@app.command("check-repo-pipeline")
def check_repo_pipeline(
    repos: list[str] = typer.Argument(
        ...,
        help="Repo(s) to check: 'owner/repo', a bare 'repo' name (with --org), or a GitHub URL. "
             "Comma- or space-separated for multiple.",
    ),
    org: Optional[str] = typer.Option(None, "--org", "-o", help="Default owner/org for bare repo names (no slash)"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="GitHub PAT"),
    branch: list[str] = typer.Option(
        [], "--branch", "-b",
        help="Check this branch instead of (or in addition to) the default branch. Repeatable.",
    ),
    branch_pattern: list[str] = typer.Option(
        [], "--branch-pattern",
        help="Check branches matching this glob pattern, e.g. 'release/*'. Repeatable.",
    ),
    all_branches: bool = typer.Option(
        False, "--all-branches", help="Check every branch in the repository.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output (shows org ruleset lookup diagnostics)"),
) -> None:
    """Check whether one or more GitHub repositories have TruffleHog enabled in their CI pipeline.

    Bare repo names (no owner) fall back to --org, or if that's not given, to the
    owner of the first fully-qualified repo/URL in the list.

    By default only the repo's default branch (main/master) is checked. Use
    --branch/--branch-pattern/--all-branches to also check release branches etc.

    Examples:
        repoarmor check-repo-pipeline owner/repo
        repoarmor check-repo-pipeline https://github.com/owner/repo
        repoarmor check-repo-pipeline repo-a --org myorg
        repoarmor check-repo-pipeline repo-a,repo-b,repo-c --org myorg
        repoarmor check-repo-pipeline owner/repo-a owner/repo-b
        repoarmor check-repo-pipeline repo-a,https://github.com/myorg/repo-b
        repoarmor check-repo-pipeline owner/repo -b main -b release/2.0
        repoarmor check-repo-pipeline owner/repo --branch-pattern 'release/*'
        repoarmor check-repo-pipeline owner/repo --all-branches
    """
    setup_logging(verbose)
    if all_branches and (branch or branch_pattern):
        print_error("Use either --all-branches or --branch/--branch-pattern, not both.")
        raise typer.Exit(1)

    repo_list = [r.strip() for group in repos for r in group.split(",") if r.strip()]
    if not repo_list:
        print_error("Please provide at least one repository.")
        raise typer.Exit(1)

    inferred_org = org
    if not inferred_org:
        for r in repo_list:
            try:
                inferred_org, _ = _parse_github_owner_repo(r)
                break
            except ValueError:
                continue

    parsed: list[tuple[str, str]] = []
    for repo in repo_list:
        try:
            parsed.append(_parse_github_owner_repo(repo, default_org=inferred_org))
        except ValueError as e:
            print_error(str(e))
            raise typer.Exit(1)

    github = GitHubClient(token=token, require_token=False)

    if not (branch or branch_pattern or all_branches):
        if len(parsed) == 1:
            owner, repo_name = parsed[0]
            result = check_repo_for_trufflehog(github, owner, repo_name)

            if result.error:
                print_error(f"Could not check {result.repo_full_name}: {result.error}")
                raise typer.Exit(1)

            if result.pr_gated:
                source = "an org ruleset requiring a workflow" if result.org_ruleset_enforced else "a workflow"
                print_success(
                    f"{result.repo_full_name} ({result.visibility}): TruffleHog is enabled on pull requests "
                    f"via {source} (found in {', '.join(result.pr_gated_files)})"
                )
            elif result.has_trufflehog:
                print_warning(
                    f"{result.repo_full_name} ({result.visibility}): TruffleHog runs in CI but NOT on pull requests "
                    f"(found in {', '.join(result.matched_files)}, but none trigger on pull_request)"
                )
            else:
                print_warning(f"{result.repo_full_name} ({result.visibility}): TruffleHog is NOT enabled in the CI pipeline")
                if result.workflow_count == 0:
                    print_info("No GitHub Actions workflows found (.github/workflows is empty or missing).")
            return

        results: list[PipelineCheckResult] = []
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(check_repo_for_trufflehog, github, owner, repo_name) for owner, repo_name in parsed]
            for future in as_completed(futures):
                results.append(future.result())

        render_pipeline_check_table(results, title="TruffleHog Pipeline Coverage")

        missing = sum(1 for r in results if not r.pr_gated and not r.error)
        if missing:
            print_warning(f"{missing} of {len(results)} repositories don't run TruffleHog on pull requests.")
        return

    if branch and not (branch_pattern or all_branches):
        total_tasks = len(parsed) * len(branch)
        if total_tasks > _LARGE_BRANCH_SCAN_THRESHOLD and not Confirm.ask(
            f"This will perform {total_tasks} branch checks across {len(parsed)} repositories. Continue?",
            default=False,
        ):
            raise typer.Exit(0)
    else:
        if not Confirm.ask(
            f"This will list branches for each of the {len(parsed)} repositories and check workflows on "
            "every matched branch, which can significantly increase API usage. Continue?",
            default=False,
        ):
            raise typer.Exit(0)

    results = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(
                _check_repo_across_branches, github, owner, repo_name, None, None, None,
                branch, branch_pattern, all_branches,
            )
            for owner, repo_name in parsed
        ]
        for future in as_completed(futures):
            results.extend(future.result())

    if not results:
        print_warning("No branches matched --branch/--branch-pattern in any of the given repositories.")
        return

    if len(results) == 1:
        result = results[0]
        branch_label = f" [{result.branch}]" if result.branch else ""

        if result.error:
            print_error(f"Could not check {result.repo_full_name}{branch_label}: {result.error}")
            raise typer.Exit(1)

        if result.pr_gated:
            source = "an org ruleset requiring a workflow" if result.org_ruleset_enforced else "a workflow"
            print_success(
                f"{result.repo_full_name}{branch_label} ({result.visibility}): TruffleHog is enabled on pull "
                f"requests via {source} (found in {', '.join(result.pr_gated_files)})"
            )
        elif result.has_trufflehog:
            print_warning(
                f"{result.repo_full_name}{branch_label} ({result.visibility}): TruffleHog runs in CI but NOT "
                f"on pull requests (found in {', '.join(result.matched_files)}, but none trigger on pull_request)"
            )
        else:
            print_warning(
                f"{result.repo_full_name}{branch_label} ({result.visibility}): TruffleHog is NOT enabled in the CI pipeline"
            )
            if result.workflow_count == 0:
                print_info("No GitHub Actions workflows found (.github/workflows is empty or missing).")
        return

    render_pipeline_check_table(results, title="TruffleHog Pipeline Coverage")

    missing = sum(1 for r in results if not r.pr_gated and not r.error)
    if missing:
        print_warning(f"{missing} of {len(results)} branch checks don't run TruffleHog on pull requests.")


@app.command("check-org-pipeline")
def check_org_pipeline(
    org: str = typer.Argument(..., help="GitHub organization to check"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="GitHub PAT"),
    include_archived: bool = typer.Option(False, "--include-archived", help="Include archived repos"),
    include_private: bool = typer.Option(True, "--include-private/--public-only", help="Include private repos"),
    missing_only: bool = typer.Option(False, "--missing-only", help="Only show repos missing TruffleHog"),
    branch: list[str] = typer.Option(
        [], "--branch", "-b",
        help="Check this branch instead of the default branch for every repo. Repeatable.",
    ),
    branch_pattern: list[str] = typer.Option(
        [], "--branch-pattern",
        help="Check branches matching this glob pattern, e.g. 'release/*'. Repeatable.",
    ),
    all_branches: bool = typer.Option(
        False, "--all-branches", help="Check every branch of every repository in the org.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output (shows org ruleset lookup diagnostics)"),
) -> None:
    """Scan all repositories in a GitHub organization and report which ones have
    TruffleHog enabled in their CI pipeline (GitHub Actions workflows).

    By default only each repo's default branch (main/master) is checked. Use
    --branch/--branch-pattern/--all-branches to also cover release branches etc.
    These options multiply the number of API calls (one branch listing plus one
    workflow scan per matched branch, per repo), so use them with care on large orgs.

    Example:
        repoarmor check-org-pipeline mycompany
        repoarmor check-org-pipeline mycompany --branch-pattern 'release/*'
    """
    setup_logging(verbose)
    if all_branches and (branch or branch_pattern):
        print_error("Use either --all-branches or --branch/--branch-pattern, not both.")
        raise typer.Exit(1)

    github = GitHubClient(token=token, require_token=include_private)

    if not github.validate_org_access(org):
        print_error(f"Cannot access organization: {org}. Check the org name and token permissions.")
        raise typer.Exit(1)

    try:
        repos = list(github.get_org_repos(
            org,
            include_private=include_private,
            include_archived=include_archived,
        ))
    except GitHubAPIError as e:
        print_error(str(e))
        raise typer.Exit(1)

    if not repos:
        print_warning(f"No repositories found in: {org}")
        raise typer.Exit(0)

    branch_mode = bool(branch or branch_pattern or all_branches)

    if branch_mode:
        if branch and not (branch_pattern or all_branches):
            total_tasks = len(repos) * len(branch)
            if total_tasks > _LARGE_BRANCH_SCAN_THRESHOLD and not Confirm.ask(
                f"This will perform {total_tasks} branch checks across {len(repos)} repositories. Continue?",
                default=False,
            ):
                raise typer.Exit(0)
        else:
            if not Confirm.ask(
                f"This will list branches for each of the {len(repos)} repositories and check workflows on "
                "every matched branch, which can significantly increase API usage. Continue?",
                default=False,
            ):
                raise typer.Exit(0)

    console.print(f"[info]Checking {len(repos)} repositories in '{org}' for TruffleHog pipeline coverage...[/info]")

    results: list[PipelineCheckResult] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Checking...", total=len(repos))

        with ThreadPoolExecutor(max_workers=8) as executor:
            if branch or branch_pattern or all_branches:
                futures = {
                    executor.submit(
                        _check_repo_across_branches, github, org, r.name, r.url, r.visibility, r.default_branch,
                        branch, branch_pattern, all_branches,
                    ): r
                    for r in repos
                }
                for future in as_completed(futures):
                    results.extend(future.result())
                    progress.advance(task)
            else:
                futures = {
                    executor.submit(check_repo_for_trufflehog, github, org, r.name, r.url, r.visibility, r.default_branch): r
                    for r in repos
                }
                for future in as_completed(futures):
                    results.append(future.result())
                    progress.advance(task)

    if branch_mode and not results:
        print_warning("No branches matched --branch/--branch-pattern in any repository in this org.")
        raise typer.Exit(0)

    if missing_only:
        results = [r for r in results if not r.pr_gated and not r.error]

    render_pipeline_check_table(results, title=f"TruffleHog Pipeline Coverage — {org}")

    missing = sum(1 for r in results if not r.pr_gated and not r.error)
    if missing:
        target_label = "branch checks" if branch_mode else "repositories"
        print_warning(f"{missing} {target_label} don't run TruffleHog on pull requests.")



@app.command("search-repo-workflows")
def search_repo_workflows_cmd(
    repos: list[str] = typer.Argument(
        ...,
        help="Repo(s) to search: 'owner/repo', a bare 'repo' name (with --org), or a GitHub URL. "
             "Comma- or space-separated for multiple.",
    ),
    pattern: str = typer.Option(..., "--pattern", "-p", help="String or regex to search for in workflow files (e.g. 'trivy')"),
    regex: bool = typer.Option(False, "--regex", help="Treat --pattern as a regular expression instead of a literal string"),
    org: Optional[str] = typer.Option(None, "--org", "-o", help="Default owner/org for bare repo names (no slash)"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="GitHub PAT"),
    branch: list[str] = typer.Option(
        [], "--branch", "-b",
        help="Search this branch instead of (or in addition to) the default branch. Repeatable.",
    ),
    branch_pattern: list[str] = typer.Option(
        [], "--branch-pattern",
        help="Search branches matching this glob pattern, e.g. 'release/*'. Repeatable.",
    ),
    all_branches: bool = typer.Option(
        False, "--all-branches", help="Search every branch in the repository.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Search one or more GitHub repositories' CI workflows for a custom string or regex pattern.

    By default only the repo's default branch (main/master) is searched. Use
    --branch/--branch-pattern/--all-branches to also search release branches etc.

    Examples:
        repoarmor search-repo-workflows owner/repo --pattern trivy
        repoarmor search-repo-workflows repo-a repo-b --org myorg --pattern "snyk|trivy" --regex
        repoarmor search-repo-workflows owner/repo --pattern trivy -b main -b release/2.0
        repoarmor search-repo-workflows owner/repo --pattern trivy --all-branches
    """
    setup_logging(verbose)
    if all_branches and (branch or branch_pattern):
        print_error("Use either --all-branches or --branch/--branch-pattern, not both.")
        raise typer.Exit(1)

    repo_list = [r.strip() for group in repos for r in group.split(",") if r.strip()]
    if not repo_list:
        print_error("Please provide at least one repository.")
        raise typer.Exit(1)

    inferred_org = org
    if not inferred_org:
        for r in repo_list:
            try:
                inferred_org, _ = _parse_github_owner_repo(r)
                break
            except ValueError:
                continue

    parsed: list[tuple[str, str]] = []
    for repo in repo_list:
        try:
            parsed.append(_parse_github_owner_repo(repo, default_org=inferred_org))
        except ValueError as e:
            print_error(str(e))
            raise typer.Exit(1)

    if regex:
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            print_error(f"Invalid regex pattern: {e}")
            raise typer.Exit(1)

    github = GitHubClient(token=token, require_token=False)

    if not (branch or branch_pattern or all_branches):
        if len(parsed) == 1:
            owner, repo_name = parsed[0]
            result = search_repo_workflows(github, owner, repo_name, pattern, use_regex=regex)

            if result.error:
                print_error(f"Could not search {result.repo_full_name}: {result.error}")
                raise typer.Exit(1)

            escaped_pattern = escape(pattern)
            if result.found:
                escaped_files = ", ".join(escape(path) for path in result.matched_files)
                print_success(f"{result.repo_full_name}: '{escaped_pattern}' found in {escaped_files}")
            else:
                print_warning(f"{result.repo_full_name}: '{escaped_pattern}' not found in any workflow")
            return

        results: list[WorkflowSearchResult] = []
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(search_repo_workflows, github, owner, repo_name, pattern, regex)
                for owner, repo_name in parsed
            ]
            for future in as_completed(futures):
                results.append(future.result())

        render_workflow_search_table(results, pattern)
        return

    if branch and not (branch_pattern or all_branches):
        total_tasks = len(parsed) * len(branch)
        if total_tasks > _LARGE_BRANCH_SCAN_THRESHOLD and not Confirm.ask(
            f"This will perform {total_tasks} branch searches across {len(parsed)} repositories. Continue?",
            default=False,
        ):
            raise typer.Exit(0)
    else:
        if not Confirm.ask(
            f"This will list branches for each of the {len(parsed)} repositories and search workflows on "
            "every matched branch, which can significantly increase API usage. Continue?",
            default=False,
        ):
            raise typer.Exit(0)

    results = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(
                _search_repo_workflows_across_branches, github, owner, repo_name, pattern, regex, None, None,
                branch, branch_pattern, all_branches,
            )
            for owner, repo_name in parsed
        ]
        for future in as_completed(futures):
            results.extend(future.result())

    if not results:
        print_warning("No branches matched --branch/--branch-pattern in any of the given repositories.")
        return

    if len(results) == 1:
        result = results[0]
        branch_label = f" [{result.branch}]" if result.branch else ""

        if result.error:
            print_error(f"Could not search {result.repo_full_name}{branch_label}: {result.error}")
            raise typer.Exit(1)

        escaped_pattern = escape(pattern)
        if result.found:
            escaped_files = ", ".join(escape(path) for path in result.matched_files)
            print_success(f"{result.repo_full_name}{branch_label}: '{escaped_pattern}' found in {escaped_files}")
        else:
            print_warning(f"{result.repo_full_name}{branch_label}: '{escaped_pattern}' not found in any workflow")
        return

    render_workflow_search_table(results, pattern)


@app.command("search-org-workflows")
def search_org_workflows(
    org: str = typer.Argument(..., help="GitHub organization to search"),
    pattern: str = typer.Option(..., "--pattern", "-p", help="String or regex to search for in workflow files (e.g. 'trivy')"),
    regex: bool = typer.Option(False, "--regex", help="Treat --pattern as a regular expression instead of a literal string"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="GitHub PAT"),
    include_archived: bool = typer.Option(False, "--include-archived", help="Include archived repos"),
    include_private: bool = typer.Option(True, "--include-private/--public-only", help="Include private repos"),
    found_only: bool = typer.Option(False, "--found-only", help="Only show repos where the pattern was found"),
    branch: list[str] = typer.Option(
        [], "--branch", "-b",
        help="Search this branch instead of the default branch for every repo. Repeatable.",
    ),
    branch_pattern: list[str] = typer.Option(
        [], "--branch-pattern",
        help="Search branches matching this glob pattern, e.g. 'release/*'. Repeatable.",
    ),
    all_branches: bool = typer.Option(
        False, "--all-branches", help="Search every branch of every repository in the org.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Search all repositories in a GitHub organization's CI workflows for a custom string or regex pattern.

    By default only each repo's default branch (main/master) is searched. Use
    --branch/--branch-pattern/--all-branches to also cover release branches etc.
    These options multiply the number of API calls (one branch listing plus one
    workflow search per matched branch, per repo), so use them with care on large orgs.

    Example:
        repoarmor search-org-workflows mycompany --pattern trivy
        repoarmor search-org-workflows mycompany --pattern trivy --branch-pattern 'release/*'
    """
    setup_logging(verbose)
    if all_branches and (branch or branch_pattern):
        print_error("Use either --all-branches or --branch/--branch-pattern, not both.")
        raise typer.Exit(1)

    if regex:
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            print_error(f"Invalid regex pattern: {e}")
            raise typer.Exit(1)

    github = GitHubClient(token=token, require_token=include_private)

    if not github.validate_org_access(org):
        print_error(f"Cannot access organization: {org}. Check the org name and token permissions.")
        raise typer.Exit(1)

    try:
        repos = list(github.get_org_repos(
            org,
            include_private=include_private,
            include_archived=include_archived,
        ))
    except GitHubAPIError as e:
        print_error(str(e))
        raise typer.Exit(1)

    if not repos:
        print_warning(f"No repositories found in: {org}")
        raise typer.Exit(0)

    branch_mode = bool(branch or branch_pattern or all_branches)

    if branch_mode:
        if branch and not (branch_pattern or all_branches):
            total_tasks = len(repos) * len(branch)
            if total_tasks > _LARGE_BRANCH_SCAN_THRESHOLD and not Confirm.ask(
                f"This will perform {total_tasks} branch searches across {len(repos)} repositories. Continue?",
                default=False,
            ):
                raise typer.Exit(0)
        else:
            if not Confirm.ask(
                f"This will list branches for each of the {len(repos)} repositories and search workflows on "
                "every matched branch, which can significantly increase API usage. Continue?",
                default=False,
            ):
                raise typer.Exit(0)

    console.print(
        f"[info]Searching {len(repos)} repositories in '{escape(org)}' for '{escape(pattern)}'...[/info]"
    )

    results: list[WorkflowSearchResult] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Searching...", total=len(repos))

        with ThreadPoolExecutor(max_workers=8) as executor:
            if branch or branch_pattern or all_branches:
                futures = {
                    executor.submit(
                        _search_repo_workflows_across_branches, github, org, r.name, pattern, regex, r.url, r.visibility,
                        branch, branch_pattern, all_branches,
                    ): r
                    for r in repos
                }
                for future in as_completed(futures):
                    results.extend(future.result())
                    progress.advance(task)
            else:
                futures = {
                    executor.submit(search_repo_workflows, github, org, r.name, pattern, regex, r.url, r.visibility): r
                    for r in repos
                }
                for future in as_completed(futures):
                    results.append(future.result())
                    progress.advance(task)

    if branch_mode and not results:
        print_warning("No branches matched --branch/--branch-pattern in any repository in this org.")
        raise typer.Exit(0)

    total_results = len(results)
    found_count = sum(1 for r in results if r.found)
    if found_only:
        results = [r for r in results if r.found and not r.error]

    render_workflow_search_table(results, pattern, title=f"Workflow Search — {org}")

    target_label = "branch checks" if branch_mode else "repositories"
    print_info(f"'{escape(pattern)}' found in {found_count} of {total_results} {target_label} searched.")


@app.command("check-org-members")
def check_org_members(
    org: str = typer.Argument(..., help="GitHub organization slug"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="GitHub PAT with read:org scope"),
    internal_domain: Optional[list[str]] = typer.Option(
        None, "--internal-domain", "-d",
        help="Email domain considered internal (repeatable). Defaults to config's identity.internal_email_domains.",
    ),
    external_only: bool = typer.Option(False, "--external-only", help="Only show members classified as external"),
) -> None:
    """Classify all members of a GitHub organization as internal or external based on email domain.

    Emails are looked up via each user's public profile, falling back to their git
    commit author email (found via the Search API) when the profile email is private.
    Members with no discoverable email are marked 'unknown', not 'external'.

    Example:
        repoarmor check-org-members mycompany --internal-domain mycompany.com
    """
    settings = get_settings()
    domains = internal_domain or settings.identity.internal_email_domains
    if not domains:
        print_error(
            "No internal email domains configured. Pass --internal-domain (e.g. -d mycompany.com) "
            "or set identity.internal_email_domains in your config file."
        )
        raise typer.Exit(1)

    github = GitHubClient(token=token, require_token=False)
    try:
        members_iter, public_only_used = github.get_org_members(org)
        members = list(members_iter)
    except GitHubAPIError as e:
        print_error(str(e))
        raise typer.Exit(1)

    if public_only_used:
        print_warning(f"Not an org member — showing only members who have made their membership public.")

    if not members:
        print_warning(f"No members found in org '{org}'.")
        raise typer.Exit(0)

    default_permission = github.get_org_default_permission(org)
    if default_permission and default_permission != "none":
        print_info(
            f"Org default repository permission is '{default_permission}' - every member likely has "
            f"{default_permission} access to every repo (public, private, and internal) in '{org}', "
            "even without being an explicit collaborator."
        )
    elif default_permission is None:
        print_info(
            "Could not read the org's default repository permission (requires an org-owner token) - "
            "members may still have implicit access to all repos if it's not set to 'none'."
        )

    console.print(f"[info]Checking {len(members)} members of '{org}' against domains: {', '.join(domains)}...[/info]")
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Checking... (throttled to respect GitHub's Search API limits)", total=len(members))
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(classify_member, github, username, domains, org, None) for username in members]
            for future in as_completed(futures):
                results.append(future.result())
                progress.advance(task)

    if external_only:
        results = [r for r in results if r.status == "external"]

    render_member_check_table(results, title=f"Member Identity Check — {org}")

    external = sum(1 for r in results if r.status == "external")
    unknown = sum(1 for r in results if r.status == "unknown")
    if external:
        print_warning(f"{external} member(s) appear external to {', '.join(domains)}.")
    if unknown:
        print_info(f"{unknown} member(s) had no discoverable email (neither public profile nor commits).")


@app.command("check-repo-collaborators")
def check_repo_collaborators(
    repo: str = typer.Argument(..., help="Repo to check: 'owner/repo' or a GitHub URL"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="GitHub PAT"),
    internal_domain: Optional[list[str]] = typer.Option(
        None, "--internal-domain", "-d",
        help="Email domain considered internal (repeatable). Defaults to config's identity.internal_email_domains.",
    ),
    external_only: bool = typer.Option(False, "--external-only", help="Only show collaborators classified as external"),
    affiliation: str = typer.Option(
        "all", "--affiliation", "-a",
        help="'all' (default, includes org members with access via org-wide default permissions), "
             "'direct' (only users granted access directly; excludes team and org-default access), "
             "or 'outside' (only non-org-member collaborators).",
    ),
) -> None:
    """Classify all collaborators of a GitHub repository as internal or external based on email domain.

    Unlike check-org-members, this includes outside collaborators who aren't org members at all.
    Note: with the default --affiliation all, this can include every org member if the org grants a
    default repository permission to all members. Use --affiliation direct to inspect only users
    granted access directly; team-based access is not included.

    Example:
        repoarmor check-repo-collaborators myorg/myrepo --internal-domain mycompany.com
        repoarmor check-repo-collaborators myorg/myrepo --affiliation direct
    """
    if affiliation not in ("all", "direct", "outside"):
        print_error("--affiliation must be one of: all, direct, outside")
        raise typer.Exit(1)

    settings = get_settings()
    domains = internal_domain or settings.identity.internal_email_domains
    if not domains:
        print_error(
            "No internal email domains configured. Pass --internal-domain (e.g. -d mycompany.com) "
            "or set identity.internal_email_domains in your config file."
        )
        raise typer.Exit(1)

    try:
        owner, repo_name = _parse_github_owner_repo(repo)
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)

    github = GitHubClient(token=token, require_token=False)
    try:
        collaborators = list(github.get_repo_collaborators(owner, repo_name, affiliation=affiliation))
    except GitHubAPIError as e:
        print_error(str(e))
        raise typer.Exit(1)

    if not collaborators:
        print_warning(f"No collaborators found (or accessible) for '{owner}/{repo_name}'.")
        raise typer.Exit(0)

    console.print(
        f"[info]Checking {len(collaborators)} collaborators of '{owner}/{repo_name}' "
        f"against domains: {', '.join(domains)}...[/info]"
    )
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "Checking... (throttled to respect GitHub's Search API limits)", total=len(collaborators)
        )
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(classify_member, github, username, domains, None, f"{owner}/{repo_name}")
                for username in collaborators
            ]
            for future in as_completed(futures):
                results.append(future.result())
                progress.advance(task)

    if external_only:
        results = [r for r in results if r.status == "external"]

    render_member_check_table(results, title=f"Collaborator Identity Check — {owner}/{repo_name}")

    external = sum(1 for r in results if r.status == "external")
    unknown = sum(1 for r in results if r.status == "unknown")
    if external:
        print_warning(f"{external} collaborator(s) appear external to {', '.join(domains)}.")
    if unknown:
        print_info(f"{unknown} collaborator(s) had no discoverable email (neither public profile nor commits).")


@app.command("secret-findings")
def findings(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Filter by repository URL or name"),
    org: Optional[str] = typer.Option(
        None, "--org", "-o",
        help="Filter by organization/owner name"
    ),
    detector_type: Optional[str] = typer.Option(
        None, "--type", "-t",
        help="Filter by detector type (partial match, e.g., 'aws', 'github')"
    ),
    verified: Optional[bool] = typer.Option(
        None, "--verified/--unverified",
        help="Filter by TruffleHog verification status (verified = secret confirmed active)"
    ),
    limit: Optional[int] = typer.Option(None, "--limit", "-n", help="Maximum findings to show (default: no limit)"),
    show_id: Optional[int] = typer.Option(None, "--id", help="Show detailed view of a specific finding"),
    current_only: bool = typer.Option(False, "--current-only", help="Show only secrets still present in current code (HEAD)"),
    personal: bool = typer.Option(False, "--personal", help="Show only findings from personal repos (scanned via --user / --user-org)"),
    org_only: bool = typer.Option(False, "--org-only", help="Show only findings from org repos (scanned via --org)"),
    docker: bool = typer.Option(False, "--docker", help="Show only findings from Docker image scans"),
    image: Optional[str] = typer.Option(None, "--image", "-i", help="Filter by exact Docker image name (e.g. nginx:latest)"),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="Filter by GitHub username (owner of the repo)"),
) -> None:
    """View findings with optional filters.

    Filter Options:
      --org: Filter by organization/owner (e.g., 'acme', 'microsoft')
      --repo: Filter by repository name or URL
      --type: Partial match on detector (e.g., 'aws', 'github', 'stripe')
      --verified/--unverified: TruffleHog-verified secrets (confirmed active)
      --current-only: Only show secrets still present in the current code (re-scans HEAD)
      --personal: Only findings from personal repos
      --org-only: Only findings from org repos

    Examples:
      findings --org acme --type aws
      findings --verified --type aws
      findings --repo myrepo --limit 100
      findings --id 42
      findings --org mycompany --current-only
    """
    settings = get_settings()
    init_database(settings.database.path)

    with session_scope() as session:
        # Show single finding detail
        if show_id:
            finding = queries.get_finding_by_id(session, show_id)
            if not finding:
                print_error(f"Finding not found: {show_id}")
                raise typer.Exit(1)
            render_finding_detail(finding)
            return

        # Resolve repo filter
        repo_id = None
        if repo:
            repo_obj = queries.get_repository_by_url(session, repo)
            if not repo_obj:
                # Try to find by name
                all_repos = queries.get_all_repositories(session)
                for r in all_repos:
                    if repo.lower() in r.name.lower() or repo.lower() in r.url.lower():
                        repo_obj = r
                        break
            if repo_obj:
                repo_id = repo_obj.id
            else:
                print_error(f"Repository not found: {repo}")
                raise typer.Exit(1)

        # Get findings
        # --image resolves to a repo_id the same way --repo does
        if image and not repo_id:
            img_repo = queries.get_repository_by_url(session, image)
            if img_repo:
                repo_id = img_repo.id
            else:
                print_error(f"Docker image not found in database: {image}")
                raise typer.Exit(1)

        repo_type_filter = "personal" if personal else ("org" if org_only else ("docker" if docker else None))
        found_findings = queries.get_findings(
            session,
            repo_id=repo_id,
            org=user or org,  # --user takes precedence, falls back to --org
            detector_type=detector_type,
            verified_by_trufflehog=verified,
            repo_type=repo_type_filter,
            limit=limit,
        )

        # Filter to current HEAD only if requested
        if current_only and found_findings:
            found_findings = _filter_current_only(list(found_findings))

        render_findings_table(found_findings, show_repo=(repo_id is None))


@app.command()
def dashboard() -> None:
    """Show statistics dashboard."""
    settings = get_settings()
    init_database(settings.database.path)

    with session_scope() as session:
        total_repos = queries.get_total_repos_count(session)
        total_findings = queries.get_total_findings_count(session)
        by_type = queries.get_findings_count_by_type(session)
        by_org = queries.get_findings_count_by_org(session)
        by_repo = queries.get_findings_count_by_repo(session)
        recent_scans = queries.get_recent_scans_count(session)

        render_stats_dashboard(
            total_repos=total_repos,
            total_findings=total_findings,
            findings_by_type=by_type,
            findings_by_org=by_org,
            findings_by_repo=by_repo,
            recent_scans=recent_scans,
        )


def _validate_output_path(output: Path) -> None:
    """Validate output path for security issues."""
    # Resolve to absolute path to detect traversal
    resolved = output.resolve()

    # Check for path traversal attempts
    if ".." in str(output):
        raise ValueError("Path traversal not allowed in output path")

    # Warn if writing to sensitive locations
    sensitive_paths = [
        "/etc", "/usr", "/bin", "/sbin", "/var", "/root", "/sys", "/proc",  # Linux
        "/Library", "/System", "/Applications",  # macOS
        "/private/etc", "/private/var",  # macOS private (but allow /private/tmp)
    ]
    for sensitive in sensitive_paths:
        if str(resolved).startswith(sensitive):
            raise ValueError(f"Cannot write to sensitive location: {sensitive}")

    # Ensure parent directory exists and is writable
    parent = resolved.parent
    if not parent.exists():
        raise ValueError(f"Parent directory does not exist: {parent}")


@app.command()
def report(
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv, markdown"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Filter by repository"),
    org: Optional[str] = typer.Option(None, "--org", help="Filter by organization/owner name"),
    current_only: bool = typer.Option(False, "--current-only", help="Show only secrets still present in current code (HEAD)"),
) -> None:
    """Generate a findings report."""
    settings = get_settings()
    init_database(settings.database.path)

    # Validate output path if provided
    if output:
        try:
            _validate_output_path(output)
        except ValueError as e:
            print_error(str(e))
            raise typer.Exit(1)

    with session_scope() as session:
        # Resolve repo filter
        repo_id = None
        if repo:
            repo_obj = queries.get_repository_by_url(session, repo)
            if repo_obj:
                repo_id = repo_obj.id

        findings_list = queries.get_findings(session, repo_id=repo_id, org=org)

        # Filter to current HEAD only if requested
        if current_only and findings_list:
            findings_list = _filter_current_only(list(findings_list))

        if format == "table":
            render_findings_table(findings_list)
            return

        # Build report data
        report_data = []
        for f in findings_list:
            report_data.append({
                "id": f.id,
                "repository": f.repository.name if f.repository else "unknown",
                "visibility": f.repository.visibility if f.repository else "public",
                "detector_type": f.detector_type,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "commit": f.commit,
                "verified_by_trufflehog": f.verified_by_trufflehog,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            })

        if format == "json":
            output_text = json.dumps(report_data, indent=2)
        elif format == "csv":
            import csv
            import io
            output_buffer = io.StringIO()
            if report_data:
                writer = csv.DictWriter(output_buffer, fieldnames=report_data[0].keys())
                writer.writeheader()
                writer.writerows(report_data)
            output_text = output_buffer.getvalue()
        elif format == "markdown":
            lines = ["# RepoArmor Report", ""]
            lines.append(f"**Total findings:** {len(report_data)}")
            lines.append("")
            if report_data:
                # Summary by repo
                from collections import Counter
                repo_counts = Counter(r["repository"] for r in report_data)
                type_counts = Counter(r["detector_type"] for r in report_data)
                verified_count = sum(1 for r in report_data if r["verified_by_trufflehog"])

                lines.append("## Summary")
                lines.append("")
                lines.append(f"- **Repositories affected:** {len(repo_counts)}")
                lines.append(f"- **Verified (active) secrets:** {verified_count}")
                lines.append("")

                lines.append("### Findings by Repository")
                lines.append("")
                lines.append("| Repository | Visibility | Findings |")
                lines.append("|------------|------------|----------|")
                for repo_name, count in repo_counts.most_common():
                    vis = next((r["visibility"] for r in report_data if r["repository"] == repo_name), "unknown")
                    lines.append(f"| {repo_name} | {vis} | {count} |")
                lines.append("")

                lines.append("### Findings by Detector Type")
                lines.append("")
                lines.append("| Detector | Count |")
                lines.append("|----------|-------|")
                for dtype, count in type_counts.most_common():
                    lines.append(f"| {dtype} | {count} |")
                lines.append("")

                lines.append("## All Findings")
                lines.append("")
                lines.append("| ID | Repository | Detector | File | Verified | Commit |")
                lines.append("|----|------------|----------|------|----------|--------|")
                for r in report_data:
                    verified_mark = "Yes" if r["verified_by_trufflehog"] else "No"
                    commit_short = r["commit"][:7] if r["commit"] else "-"
                    file_info = r["file_path"]
                    if r["line_number"]:
                        file_info += f":{r['line_number']}"
                    lines.append(f"| {r['id']} | {r['repository']} | {r['detector_type']} | {file_info} | {verified_mark} | {commit_short} |")

            output_text = "\n".join(lines)
        else:
            print_error(f"Unknown format: {format}")
            raise typer.Exit(1)

        if output:
            with open(output, "w") as f:
                f.write(output_text)
            print_success(f"Report saved to {output}")
        else:
            console.print(output_text)


# Export/Import commands for sharing scan results

@app.command("export")
def export_data(
    output_file: Path = typer.Argument(..., help="Output JSON file path"),
    org: Optional[str] = typer.Option(None, "--org", "-o", help="Filter by organization"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Filter by repository name"),
) -> None:
    """Export scan results to JSON for sharing with other users.

    This allows sharing scan results without re-scanning the same repositories.

    Examples:
        repoarmor export results.json
        repoarmor export acme-results.json --org acme
        repoarmor export repo-results.json --repo acme/service
    """
    settings = get_settings()
    init_database(settings.database.path)

    # Validate output path
    try:
        _validate_output_path(output_file)
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)

    with session_scope() as session:
        # Get repositories to export
        repos = queries.get_repositories_for_export(session, org=org, repo_name=repo)

        if not repos:
            print_warning("No repositories found matching the filter")
            raise typer.Exit(0)

        # Build export data
        export_repos = []
        export_findings = []

        for r in repos:
            export_repos.append({
                "url": r.url,
                "name": r.name,
                "visibility": r.visibility,
                "last_scanned": r.last_scanned.isoformat() if r.last_scanned else None,
                "total_findings": r.total_findings,
            })

            # Get findings for this repo
            findings = queries.get_findings_by_repo(session, r.id)
            for f in findings:
                export_findings.append({
                    "repository_url": r.url,
                    "detector_type": f.detector_type,
                    "decoder_type": f.decoder_type,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "commit": f.commit,
                    "author": f.author,
                    "author_email": f.author_email,
                    "commit_date": f.commit_date.isoformat() if f.commit_date else None,
                    "message": f.message,
                    "secret_hash": f.secret_hash,
                    "redacted_secret": f.redacted_secret,
                    "verified_by_trufflehog": f.verified_by_trufflehog,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                    "updated_at": f.updated_at.isoformat() if f.updated_at else None,
                })

        export_data = {
            "version": "1.0",
            "exported_at": datetime.now().isoformat(),
            "repositories": export_repos,
            "findings": export_findings,
        }

        # Write to file
        with open(output_file, "w") as f:
            json.dump(export_data, f, indent=2)

        print_success(f"Exported {len(export_repos)} repositories and {len(export_findings)} findings to {output_file}")


@app.command("import")
def import_data(
    input_file: Path = typer.Argument(..., help="Input JSON file path"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Preview what would be imported without making changes"),
) -> None:
    """Import scan results from JSON file.

    Uses smart merge by default - skips findings that already exist (by secret_hash).

    Examples:
        repoarmor import results.json
        repoarmor import results.json --dry-run
    """
    settings = get_settings()
    init_database(settings.database.path)

    # Validate input file
    if not input_file.exists():
        print_error(f"File not found: {input_file}")
        raise typer.Exit(1)

    # Load and validate JSON
    try:
        with open(input_file, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print_error(f"Invalid JSON: {e}")
        raise typer.Exit(1)

    # Validate structure
    if "version" not in data or "repositories" not in data or "findings" not in data:
        print_error("Invalid export file format. Missing required fields: version, repositories, findings")
        raise typer.Exit(1)

    repos_data = data.get("repositories", [])
    findings_data = data.get("findings", [])

    console.print(f"[info]Found {len(repos_data)} repositories and {len(findings_data)} findings in export file[/info]")

    if dry_run:
        console.print("[warning]DRY RUN - no changes will be made[/warning]\n")

    # Track stats
    new_repos = 0
    existing_repos = 0
    new_findings = 0
    skipped_findings = 0

    with session_scope() as session:
        # First pass: create/lookup repositories
        repo_url_to_id = {}
        for repo_data in repos_data:
            url = repo_data.get("url")
            name = repo_data.get("name")

            if not url or not name:
                print_warning(f"Skipping repository with missing url or name")
                continue

            existing_repo = queries.get_repository_by_url(session, url)
            if existing_repo:
                repo_url_to_id[url] = existing_repo.id
                existing_repos += 1
            else:
                if not dry_run:
                    # Support both old "is_private" and new "visibility" format
                    visibility = repo_data.get("visibility")
                    if visibility is None:
                        visibility = "private" if repo_data.get("is_private", False) else "public"
                    new_repo = queries.create_repository(session, url, name, visibility)
                    repo_url_to_id[url] = new_repo.id
                else:
                    repo_url_to_id[url] = -1  # Placeholder for dry run
                new_repos += 1

        # Second pass: import findings
        for finding_data in findings_data:
            repo_url = finding_data.get("repository_url")
            secret_hash = finding_data.get("secret_hash")

            if not repo_url or not secret_hash:
                print_warning(f"Skipping finding with missing repository_url or secret_hash")
                continue

            if repo_url not in repo_url_to_id:
                print_warning(f"Skipping finding for unknown repository: {repo_url}")
                continue

            repo_id = repo_url_to_id[repo_url]

            # Check if finding already exists
            if not dry_run and repo_id > 0:
                existing_finding = queries.get_findings_by_secret_hash(session, repo_id, secret_hash)
            else:
                existing_finding = None

            if existing_finding:
                skipped_findings += 1
            else:
                # Create new finding
                if not dry_run and repo_id > 0:
                    # Parse datetime fields
                    commit_date = None
                    if finding_data.get("commit_date"):
                        try:
                            commit_date = datetime.fromisoformat(finding_data["commit_date"])
                        except ValueError:
                            pass

                    queries.create_finding(
                        session,
                        repo_id=repo_id,
                        detector_type=finding_data.get("detector_type", "Unknown"),
                        decoder_type=finding_data.get("decoder_type"),
                        file_path=finding_data.get("file_path", ""),
                        line_number=finding_data.get("line_number"),
                        commit=finding_data.get("commit"),
                        author=finding_data.get("author"),
                        author_email=finding_data.get("author_email"),
                        commit_date=commit_date,
                        message=finding_data.get("message"),
                        secret_hash=secret_hash,
                        redacted_secret=finding_data.get("redacted_secret"),
                        verified_by_trufflehog=finding_data.get("verified_by_trufflehog", False),
                    )
                new_findings += 1

        # Update repository stats
        if not dry_run:
            for repo_url, repo_id in repo_url_to_id.items():
                if repo_id > 0:
                    repo = queries.get_repository_by_id(session, repo_id)
                    if repo:
                        queries.update_repository_stats(session, repo)

    # Print summary
    console.print("\n[header]Import Summary[/header]")
    console.print(f"  Repositories: {new_repos} new, {existing_repos} existing")
    console.print(f"  Findings: {new_findings} new, {skipped_findings} skipped (duplicates)")

    if dry_run:
        console.print("\n[warning]DRY RUN complete - no changes were made[/warning]")
    else:
        print_success("Import complete!")


# Config commands

@config_app.command("init")
def config_init(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config"),
) -> None:
    """Create default configuration file."""
    config_path = get_config_path()

    if config_path.exists() and not force:
        print_warning(f"Config already exists at {config_path}")
        if not Confirm.ask("Overwrite?"):
            raise typer.Exit(0)

    settings = get_default_config()
    save_config(settings, config_path)
    print_success(f"Created config at {config_path}")


@config_app.command("show")
def config_show() -> None:
    """Show current configuration."""
    settings = get_settings()

    table = Table(title="Current Configuration", show_lines=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value")

    table.add_row("Database Path", str(settings.database.path))
    table.add_row("TruffleHog Path", settings.scanner.trufflehog_path)
    table.add_row("Default Depth", str(settings.scanner.default_depth))
    table.add_row("Parallel Scans", str(settings.scanner.parallel_scans))
    table.add_row("Timeout", f"{settings.scanner.timeout}s")
    table.add_row("Only Verified", str(settings.scanner.only_verified))
    table.add_row("Output Format", settings.output.default_format)
    table.add_row("Ignore Patterns", ", ".join(settings.ignore_patterns[:5]) + "...")
    table.add_row("LLM Provider", settings.llm.provider)
    table.add_row("LLM Model", settings.llm.model or "(default)")
    table.add_row("LLM API Key", "***" if settings.llm.api_key else "(from env)")

    console.print(table)

    config_path = get_config_path()
    console.print(f"\n[muted]Config file: {config_path}[/muted]")


@config_app.command("path")
def config_path_cmd() -> None:
    """Show config file path."""
    console.print(str(get_config_path()))


# Chat command (LLM interface)

@app.command()
def chat(
    prompt: Optional[str] = typer.Argument(None, help="Natural language command"),
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="LLM provider (only 'openai' supported)", hidden=True),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="OpenAI model to use (default: gpt-4o)"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Interactive chat mode"),
) -> None:
    """Use natural language to interact with the scanner.

    Examples:
        repoarmor chat "show me all unverified findings"
        repoarmor chat "mark finding 5 as false positive"
        repoarmor chat -i  # Interactive mode
    """
    settings = get_settings()

    # Determine provider settings
    llm_provider = provider or settings.llm.provider
    llm_model = model or settings.llm.model
    llm_api_key = settings.llm.api_key

    try:
        from ..llm import get_llm_provider, RepoArmorAgent
    except ImportError as e:
        print_error(
            "LLM dependencies not installed. Run: pip install repoarmor[llm]"
        )
        raise typer.Exit(1)

    try:
        llm = get_llm_provider(
            provider=llm_provider,
            api_key=llm_api_key,
            model=llm_model,
        )
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)
    except ImportError as e:
        print_error(str(e))
        raise typer.Exit(1)

    agent = RepoArmorAgent(llm)

    console.print(f"[muted]Using {llm.get_model_name()}[/muted]\n")

    if interactive:
        # Interactive REPL mode
        console.print("[header]RepoArmor Chat[/header]")
        console.print("Type your commands in natural language. Type 'quit' or 'exit' to stop.\n")

        while True:
            try:
                user_input = Prompt.ask("[cyan]You[/cyan]")
            except (KeyboardInterrupt, EOFError):
                console.print("\n[muted]Goodbye![/muted]")
                break

            if user_input.lower() in ("quit", "exit", "q"):
                console.print("[muted]Goodbye![/muted]")
                break

            if user_input.lower() == "clear":
                agent.reset_conversation()
                console.print("[muted]Conversation cleared.[/muted]")
                continue

            if not user_input.strip():
                continue

            try:
                response = agent.chat(user_input)
                console.print(f"\n[green]Assistant:[/green] {response}\n")
            except Exception as e:
                print_error(f"Error: {e}")

    elif prompt:
        # Single command mode
        try:
            response = agent.chat(prompt)
            console.print(response)
        except Exception as e:
            print_error(f"Error: {e}")
            raise typer.Exit(1)
    else:
        print_error("Please provide a prompt or use --interactive mode")
        raise typer.Exit(1)


# Interactive shell with mode selection

def _run_cli_repl() -> None:
    """Run CLI command REPL."""
    settings = get_settings()
    init_database(settings.database.path)

    console.print("[header]CLI Mode[/header]")
    console.print("Available commands: scan, list, findings, dashboard, report, help, quit\n")

    while True:
        try:
            user_input = Prompt.ask("[cyan]>[/cyan]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[muted]Goodbye![/muted]")
            break

        if not user_input:
            continue

        if user_input.lower() in ("quit", "exit", "q"):
            console.print("[muted]Goodbye![/muted]")
            break

        if user_input.lower() == "help":
            console.print("""
[header]Available Commands:[/header]
  [cyan]secret-scan <url>[/cyan]           - Scan a GitHub repository
  [cyan]secret-scan --batch <file>[/cyan]  - Scan repos from file
  [cyan]list[/cyan]                        - List scanned repositories
  [cyan]secret-findings[/cyan]             - Show all findings
  [cyan]secret-findings --type <t>[/cyan]  - Filter by detector type (aws, github, etc)
  [cyan]secret-findings --id <id>[/cyan]   - Show finding details
  [cyan]dashboard[/cyan]                   - Show statistics
  [cyan]report --format json[/cyan]        - Export report
  [cyan]quit[/cyan]                        - Exit
""")
            continue

        # Parse and execute command
        parts = user_input.split()
        cmd = parts[0].lower()

        try:
            if cmd == "secret-scan":
                if len(parts) < 2:
                    print_error("Usage: secret-scan <url> or secret-scan --batch <file>")
                    continue
                if parts[1] == "--batch" and len(parts) > 2:
                    urls = validate_batch_file(parts[2])
                    for url in urls:
                        _execute_scan(url, settings)
                else:
                    _execute_scan(parts[1], settings)

            elif cmd == "list":
                with session_scope() as session:
                    repos = queries.get_all_repositories(session)
                    render_repositories_table(repos, with_stats="--with-stats" in parts or "-s" in parts)

            elif cmd == "secret-findings":
                _execute_findings(parts[1:], settings)

            elif cmd == "dashboard":
                with session_scope() as session:
                    render_stats_dashboard(
                        total_repos=queries.get_total_repos_count(session),
                        total_findings=queries.get_total_findings_count(session),
                        findings_by_type=queries.get_findings_count_by_type(session),
                        recent_scans=queries.get_recent_scans_count(session),
                    )

            elif cmd == "report":
                _execute_report(parts[1:], settings)

            else:
                print_error(f"Unknown command: {cmd}. Type 'help' for available commands.")

        except Exception as e:
            print_error(str(e))


def _execute_scan(url: str, settings) -> None:
    """Execute a scan command."""
    try:
        url = validate_repo_url(url)
    except ValueError as e:
        print_error(str(e))
        return

    if not ensure_trufflehog():
        return

    # Inject auth token if available
    scan_url = _inject_auth_token(url)

    repo_name = get_repo_name_from_url(url)
    console.print(f"[header]Scanning:[/header] [repo]{repo_name}[/repo]")

    with session_scope() as session:
        repo = queries.get_repository_by_url(session, url)
        if not repo:
            repo = queries.create_repository(session, url, repo_name)

        existing_hashes = {f.secret_hash for f in queries.get_findings_by_repo(session, repo.id)}
        findings_count = 0
        new_count = 0

        for result in scan_repository(scan_url, depth=settings.scanner.default_depth, settings=settings):
            findings_count += 1
            if result.secret_hash not in existing_hashes:
                queries.create_finding(
                    session, repo_id=repo.id, detector_type=result.detector_type,
                    decoder_type=result.decoder_type, file_path=result.file_path,
                    line_number=result.line_number, commit=result.commit,
                    author=result.author, author_email=result.author_email,
                    commit_date=result.commit_date, message=result.message,
                    secret_hash=result.secret_hash, redacted_secret=result.redacted_secret,
                    raw_finding=result.raw_finding,
                    verified_by_trufflehog=result.verified_by_trufflehog,
                )
                existing_hashes.add(result.secret_hash)
                new_count += 1

        queries.update_repository_stats(session, repo)

    if new_count > 0:
        print_warning(f"Found {new_count} new secrets ({findings_count} total)")
    else:
        print_success(f"No new secrets found ({findings_count} total)")


def _execute_findings(args: list[str], settings) -> None:
    """Execute findings command with args."""
    finding_id = None
    repo = None
    detector_type = None

    i = 0
    while i < len(args):
        if args[i] == "--type" and i + 1 < len(args):
            detector_type = args[i + 1]
            i += 2
        elif args[i] == "--id" and i + 1 < len(args):
            finding_id = int(args[i + 1])
            i += 2
        elif args[i] == "--repo" and i + 1 < len(args):
            repo = args[i + 1]
            i += 2
        else:
            i += 1

    with session_scope() as session:
        if finding_id:
            finding = queries.get_finding_by_id(session, finding_id)
            if finding:
                render_finding_detail(finding)
            else:
                print_error(f"Finding not found: {finding_id}")
        else:
            repo_id = None
            if repo:
                for r in queries.get_all_repositories(session):
                    if repo.lower() in r.name.lower():
                        repo_id = r.id
                        break

            found = queries.get_findings(session, repo_id=repo_id, detector_type=detector_type, limit=50)
            render_findings_table(found, show_repo=(repo_id is None))


def _execute_report(args: list[str], settings) -> None:
    """Execute report command with args."""
    fmt = "table"
    output_path = None

    i = 0
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]
            i += 2
        elif args[i] == "--output" and i + 1 < len(args):
            output_path = args[i + 1]
            i += 2
        else:
            i += 1

    with session_scope() as session:
        found = queries.get_findings(session)

        if fmt == "table":
            render_findings_table(found)
        else:
            report_data = [{
                "id": f.id, "repository": f.repository.name if f.repository else "unknown",
                "visibility": f.repository.visibility if f.repository else "public",
                "detector_type": f.detector_type, "file_path": f.file_path,
                "verified_by_trufflehog": f.verified_by_trufflehog,
            } for f in found]

            if fmt == "json":
                output_text = json.dumps(report_data, indent=2)
            elif fmt == "csv":
                import csv, io
                buf = io.StringIO()
                if report_data:
                    writer = csv.DictWriter(buf, fieldnames=report_data[0].keys())
                    writer.writeheader()
                    writer.writerows(report_data)
                output_text = buf.getvalue()
            else:
                print_error(f"Unknown format: {fmt}")
                return

            if output_path:
                # Validate output path for security
                try:
                    _validate_output_path(Path(output_path))
                except ValueError as e:
                    print_error(str(e))
                    return
                with open(output_path, "w") as f:
                    f.write(output_text)
                print_success(f"Report saved to {output_path}")
            else:
                console.print(output_text)


def _run_llm_repl(settings) -> None:
    """Run LLM chat REPL."""
    try:
        from ..llm import get_llm_provider, RepoArmorAgent
    except ImportError:
        print_error("LLM dependencies not installed. Run: pip install repoarmor[llm]")
        return

    # OpenAI is the only supported provider
    llm_provider = "openai"

    # Ask for model
    console.print("[header]Select Model:[/header]")
    console.print("  [cyan][1][/cyan] gpt-4o (default)")
    console.print("  [cyan][2][/cyan] gpt-4-turbo")
    console.print("  [cyan][3][/cyan] gpt-3.5-turbo")
    console.print("  [cyan][4][/cyan] Custom (enter name)")
    console.print()
    model_choice = Prompt.ask("Enter choice", default="1")
    if model_choice == "1":
        llm_model = "gpt-4o"
    elif model_choice == "2":
        llm_model = "gpt-4-turbo"
    elif model_choice == "3":
        llm_model = "gpt-3.5-turbo"
    elif model_choice == "4":
        llm_model = Prompt.ask("Enter model name")
    else:
        llm_model = model_choice  # Assume they typed a model name

    # Use config api_key as fallback
    llm_api_key = settings.llm.api_key

    console.print()
    try:
        llm = get_llm_provider(provider=llm_provider, api_key=llm_api_key, model=llm_model)
    except (ValueError, ImportError) as e:
        print_error(str(e))
        return

    agent = RepoArmorAgent(llm)

    console.print(f"[header]LLM Mode[/header] [muted]({llm.get_model_name()})[/muted]")
    console.print("Type your commands in natural language. Type 'quit' to exit, 'clear' to reset.\n")

    while True:
        try:
            user_input = Prompt.ask("[cyan]You[/cyan]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[muted]Goodbye![/muted]")
            break

        if user_input.lower() in ("quit", "exit", "q"):
            console.print("[muted]Goodbye![/muted]")
            break

        if user_input.lower() == "clear":
            agent.reset_conversation()
            console.print("[muted]Conversation cleared.[/muted]")
            continue

        if not user_input.strip():
            continue

        try:
            response = agent.chat(user_input)
            console.print(f"\n[green]Assistant:[/green] {response}\n")
        except Exception as e:
            print_error(f"Error: {e}")


@app.command("interactive")
def interactive_mode(
    mode: Optional[str] = typer.Argument(None, help="Mode to start in: 'llm' or 'cli'"),
) -> None:
    """Start interactive shell with mode selection.

    Examples:
        repoarmor interactive        # Prompts for mode
        repoarmor interactive llm    # Start directly in LLM mode
        repoarmor interactive cli    # Start directly in CLI mode
    """
    settings = get_settings()
    init_database(settings.database.path)

    # Show banner
    console.print()
    console.print("[bold cyan]╔═══════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║[/bold cyan]       [bold white]RepoArmor v0.2.0[/bold white]           [bold cyan]║[/bold cyan]")
    console.print("[bold cyan]╚═══════════════════════════════════════╝[/bold cyan]")
    console.print()

    # Determine mode
    if mode:
        selected_mode = mode.lower()
        if selected_mode not in ("llm", "cli"):
            print_error(f"Invalid mode: {mode}. Use 'llm' or 'cli'.")
            raise typer.Exit(1)
    else:
        console.print("[header]Select Mode:[/header]")
        console.print("  [cyan][1][/cyan] LLM Mode  - Natural language commands (requires API key)")
        console.print("  [cyan][2][/cyan] CLI Mode  - Traditional command interface")
        console.print()

        choice = Prompt.ask("Enter choice", choices=["1", "2", "llm", "cli"], default="2")
        selected_mode = "llm" if choice in ("1", "llm") else "cli"

    console.print()

    if selected_mode == "llm":
        _run_llm_repl(settings)
    else:
        _run_cli_repl()
