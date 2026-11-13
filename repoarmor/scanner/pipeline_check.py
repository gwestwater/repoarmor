"""Check whether a GitHub repository has TruffleHog secret scanning wired into its CI pipeline."""

import logging
import re
import threading
from dataclasses import dataclass, field

import yaml

from .github_api import GitHubAPIError, GitHubClient

logger = logging.getLogger(__name__)

# Patterns that indicate TruffleHog is invoked, either as a marketplace GitHub Action
# or as a direct CLI call in a workflow step.
_TRUFFLEHOG_PATTERNS = [
    re.compile(r"trufflesecurity/trufflehog", re.IGNORECASE),
    re.compile(r"\btrufflehog\b", re.IGNORECASE),
]

_PR_TRIGGERS = {"pull_request", "pull_request_target"}

# Reusable workflow call syntax: `uses: owner/repo/.github/workflows/file.yml@ref` (cross-repo)
# or `uses: ./.github/workflows/file.yml` (same repo).
_EXTERNAL_REUSABLE_WORKFLOW_PATTERN = re.compile(
    r"^([\w.-]+)/([\w.-]+)/\.github/workflows/([\w./-]+\.ya?ml)@(.+)$"
)
_LOCAL_REUSABLE_WORKFLOW_PATTERN = re.compile(r"^\./\.github/workflows/([\w./-]+\.ya?ml)$")

# Cache of fetched reusable-workflow file contents, shared across repos in an org scan
# since many repos typically call the same central workflow.
_reusable_workflow_cache: dict[tuple[str, str, str, str | None], str | None] = {}
_reusable_workflow_cache_lock = threading.Lock()

# Cache of repository_id -> "owner/repo", since a "required workflow" rule referencing a
# central repo (e.g. a company-wide trufflehog-scan.yml) repeats across every repo in an org scan.
_repo_id_cache: dict[int, dict | None] = {}
_repo_id_cache_lock = threading.Lock()


@dataclass
class RequiredWorkflowMatch:
    """A "required workflow" rule enforced on a repo via an org-level ruleset.

    GitHub can enforce a reusable workflow (e.g. a central TruffleHog scan) on a
    repo via a ruleset, without that workflow ever appearing in the target repo's
    own .github/workflows directory. GitHub always runs these on pull requests.
    """
    ref_owner: str
    ref_repo: str
    ref_path: str
    ref_branch: str | None
    ruleset_source: str
    is_org_ruleset: bool


@dataclass
class PipelineCheckResult:
    """Result of checking a single repository for TruffleHog CI integration."""
    repo_full_name: str
    repo_url: str
    has_trufflehog: bool
    matched_files: list[str] = field(default_factory=list)
    pr_gated_files: list[str] = field(default_factory=list)
    workflow_count: int = 0
    visibility: str = "unknown"
    error: str | None = None
    org_ruleset_enforced: bool = False
    branch: str = ""

    @property
    def pr_gated(self) -> bool:
        """True if TruffleHog runs on pull_request/pull_request_target in at least one workflow."""
        return bool(self.pr_gated_files)


def _content_has_trufflehog(content: str) -> bool:
    direct_match, _, _ = _analyze_workflow_content(content, "", "")
    return direct_match


def _condition_allows_pr(condition: str | None) -> bool:
    """Conservatively determine whether a job/step condition can run on PR events."""
    if not isinstance(condition, str):
        return True

    normalized = condition.strip()
    lowered = normalized.lower()
    if "pull_request" not in lowered:
        return True

    if re.search(r"github\.event_name\s*!=\s*['\"]pull_request(?:_target)?['\"]", normalized, re.IGNORECASE):
        return False

    return bool(
        re.search(
            r"github\.event_name\s*==\s*['\"]pull_request(?:_target)?['\"]",
            normalized,
            re.IGNORECASE,
        )
    )


def _analyze_workflow_content(
    content: str, owner: str, repo: str
) -> tuple[bool, bool, list[tuple[str, str, str, str | None, bool]]]:
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return False, False, []
    if not isinstance(data, dict):
        return False, False, []

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return False, False, []

    has_trufflehog = False
    pr_eligible_match = False
    reusable_refs: list[tuple[str, str, str, str | None, bool]] = []
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        job_pr_eligible = _condition_allows_pr(job.get("if"))
        job_uses = job.get("uses")
        if isinstance(job_uses, str):
            if any(pattern.search(job_uses) for pattern in _TRUFFLEHOG_PATTERNS):
                has_trufflehog = True
                if job_pr_eligible:
                    pr_eligible_match = True
            external_match = _EXTERNAL_REUSABLE_WORKFLOW_PATTERN.match(job_uses)
            if external_match:
                reusable_refs.append(
                    (
                        external_match.group(1),
                        external_match.group(2),
                        f".github/workflows/{external_match.group(3)}",
                        external_match.group(4),
                        job_pr_eligible,
                    )
                )
                continue
            local_match = _LOCAL_REUSABLE_WORKFLOW_PATTERN.match(job_uses)
            if local_match:
                reusable_refs.append(
                    (owner, repo, f".github/workflows/{local_match.group(1)}", None, job_pr_eligible)
                )
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            step_pr_eligible = job_pr_eligible and _condition_allows_pr(step.get("if"))
            step_uses = step.get("uses")
            if isinstance(step_uses, str) and any(pattern.search(step_uses) for pattern in _TRUFFLEHOG_PATTERNS):
                has_trufflehog = True
                if step_pr_eligible:
                    pr_eligible_match = True
            step_run = step.get("run")
            if isinstance(step_run, str) and any(pattern.search(step_run) for pattern in _TRUFFLEHOG_PATTERNS):
                has_trufflehog = True
                if step_pr_eligible:
                    pr_eligible_match = True
    return has_trufflehog, pr_eligible_match, reusable_refs


def _find_reusable_workflow_refs(content: str, owner: str, repo: str) -> list[tuple[str, str, str, str | None]]:
    """Find reusable workflow calls in a workflow file, returning (owner, repo, path, ref) tuples."""
    _, _, refs = _analyze_workflow_content(content, owner, repo)
    return [(ref_owner, ref_repo, ref_path, ref) for ref_owner, ref_repo, ref_path, ref, _ in refs]


def _get_cached_workflow_content(github: GitHubClient, owner: str, repo: str, path: str, ref: str | None = None) -> str | None:
    """Fetch a workflow file's content, caching across calls to avoid refetching shared workflows."""
    key = (owner, repo, path, ref)
    with _reusable_workflow_cache_lock:
        if key in _reusable_workflow_cache:
            return _reusable_workflow_cache[key]
    content = github.get_file_content(owner, repo, path, ref=ref)
    with _reusable_workflow_cache_lock:
        _reusable_workflow_cache[key] = content
    return content


def _workflow_has_trufflehog(
    github: GitHubClient,
    content: str,
    owner: str,
    repo: str,
    stack: set[tuple[str, str, str, str | None]] | None = None,
) -> tuple[bool, bool]:
    """Check whether a workflow directly or transitively invokes TruffleHog."""
    if stack is None:
        stack = set()

    has_trufflehog, pr_eligible_match, reusable_refs = _analyze_workflow_content(content, owner, repo)
    for ref_owner, ref_repo, ref_path, ref, pr_eligible in reusable_refs:
        cache_key = (ref_owner, ref_repo, ref_path, ref)
        if cache_key in stack:
            continue

        stack.add(cache_key)
        try:
            ref_content = _get_cached_workflow_content(
                github,
                ref_owner,
                ref_repo,
                ref_path,
                ref=ref,
            )
            if not ref_content:
                continue
            ref_has_trufflehog, ref_pr_eligible = _workflow_has_trufflehog(
                github,
                ref_content,
                ref_owner,
                ref_repo,
                stack=stack,
            )
        finally:
            stack.remove(cache_key)

        if ref_has_trufflehog:
            has_trufflehog = True
            if pr_eligible and ref_pr_eligible:
                pr_eligible_match = True

    return has_trufflehog, pr_eligible_match


def _workflow_triggers_on_pr(content: str) -> bool:
    """Check if a workflow YAML's trigger config includes pull_request(_target).

    YAML 1.1 parses the bare 'on:' key as a boolean, so PyYAML turns it into the
    key `True` instead of the string "on" - both are checked here.
    """
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return False
    if not isinstance(data, dict):
        return False

    triggers = data.get("on", data.get(True))
    if isinstance(triggers, str):
        trigger_names = {triggers}
    elif isinstance(triggers, list):
        trigger_names = {str(t) for t in triggers}
    elif isinstance(triggers, dict):
        trigger_names = {str(k) for k in triggers.keys()}
    else:
        trigger_names = set()

    return bool(trigger_names & _PR_TRIGGERS)


def _repo_id_to_full_name(github: GitHubClient, repo_id: int) -> tuple[str, str] | None:
    """Resolve a numeric repository ID to (owner, repo), caching across calls."""
    with _repo_id_cache_lock:
        cached = repo_id in _repo_id_cache
        info = _repo_id_cache.get(repo_id)
    if not cached:
        try:
            info = github.get_repo_by_id(repo_id)
        except GitHubAPIError as e:
            logger.warning("Could not resolve repository_id %s: %s", repo_id, e)
            info = None
        with _repo_id_cache_lock:
            _repo_id_cache[repo_id] = info
    if not info or "/" not in info.get("full_name", ""):
        return None
    owner, repo = info["full_name"].split("/", 1)
    return owner, repo


def _find_required_workflow_matches(github: GitHubClient, owner: str, repo: str, branch: str) -> list[RequiredWorkflowMatch]:
    """Fetch the effective rules for a repo's branch and extract any required "workflows" rules.

    This uses the per-repo "effective rules" endpoint rather than listing org rulesets
    directly: GitHub resolves which org-level rulesets apply to this repo/branch for us,
    and it only needs normal repo-read access (listing org rulesets requires organization
    admin permissions, which most tokens don't have).
    """
    try:
        effective_rules = github.get_branch_rules(owner, repo, branch)
    except GitHubAPIError as e:
        logger.warning("Could not fetch effective branch rules for '%s/%s': %s", owner, repo, e)
        return []

    matches: list[RequiredWorkflowMatch] = []
    for rule in effective_rules:
        if rule.get("type") != "workflows":
            continue
        source = f"{rule.get('ruleset_source_type', 'ruleset')} {rule.get('ruleset_source', '')}".strip()
        for workflow in rule.get("parameters", {}).get("workflows", []) or []:
            path = workflow.get("path") or ""
            ref_repo_id = workflow.get("repository_id")
            if not path or ref_repo_id is None:
                continue
            resolved = _repo_id_to_full_name(github, ref_repo_id)
            if not resolved:
                continue
            ref_owner, ref_repo = resolved
            ref_branch = None
            git_ref = workflow.get("ref")
            if git_ref and git_ref.startswith("refs/heads/"):
                ref_branch = git_ref[len("refs/heads/"):]
            logger.debug("'%s/%s' has required workflow %s/%s/%s (ref=%s) via %s",
                         owner, repo, ref_owner, ref_repo, path, ref_branch, source)
            matches.append(RequiredWorkflowMatch(
                ref_owner=ref_owner,
                ref_repo=ref_repo,
                ref_path=path.lstrip("/"),
                ref_branch=ref_branch,
                ruleset_source=source or "org ruleset",
                is_org_ruleset=str(rule.get("ruleset_source_type", "")).lower() == "organization",
            ))
    return matches


@dataclass
class WorkflowSearchResult:
    """Result of searching a repository's GitHub Actions workflow files for a pattern."""
    repo_full_name: str
    repo_url: str
    found: bool
    matched_files: list[str] = field(default_factory=list)
    workflow_count: int = 0
    visibility: str = "unknown"
    error: str | None = None
    branch: str = ""


def search_repo_workflows(
    github: GitHubClient,
    owner: str,
    repo: str,
    pattern: str,
    use_regex: bool = False,
    repo_url: str | None = None,
    visibility: str | None = None,
    branch: str | None = None,
) -> WorkflowSearchResult:
    """Search a repository's GitHub Actions workflow files for a literal string or regex pattern.

    Args:
        github: An authenticated (or public-only) GitHubClient.
        owner: Repository owner (user or org).
        repo: Repository name.
        pattern: The literal string or regex pattern to search for.
        use_regex: If True, treat `pattern` as a regular expression instead of a literal string.
        repo_url: Optional HTML URL for display purposes.
        visibility: Repo visibility ('public', 'private', 'internal') if already known.
            If omitted, it is looked up via the GitHub API.
        branch: Specific branch to search instead of the default branch (e.g. a
            release branch). If omitted, the repo's default branch is used.

    Returns:
        WorkflowSearchResult listing which workflow files (if any) matched the pattern.
    """
    full_name = f"{owner}/{repo}"
    url = repo_url or f"https://github.com/{full_name}"

    if visibility is None:
        try:
            repo_data = github.get_repo_info(owner, repo)
        except GitHubAPIError as e:
            return WorkflowSearchResult(repo_full_name=full_name, repo_url=url, found=False, error=str(e), branch=branch or "")
        if repo_data is None:
            return WorkflowSearchResult(
                repo_full_name=full_name, repo_url=url, found=False,
                error="Repository not found or inaccessible.", branch=branch or "",
            )
        visibility = repo_data.get("visibility") or ("private" if repo_data.get("private") else "public")

    try:
        workflow_paths = github.list_workflow_files(owner, repo, ref=branch)
    except GitHubAPIError as e:
        return WorkflowSearchResult(
            repo_full_name=full_name, repo_url=url, found=False, visibility=visibility, error=str(e), branch=branch or ""
        )

    try:
        matcher = re.compile(pattern if use_regex else re.escape(pattern), re.IGNORECASE)
    except re.error as e:
        return WorkflowSearchResult(
            repo_full_name=full_name, repo_url=url, found=False,
            workflow_count=len(workflow_paths), visibility=visibility,
            error=f"Invalid regex pattern: {e}", branch=branch or "",
        )

    matched_files: list[str] = []
    for path in workflow_paths:
        try:
            content = github.get_file_content(owner, repo, path, ref=branch)
        except GitHubAPIError as e:
            return WorkflowSearchResult(
                repo_full_name=full_name, repo_url=url, found=False,
                workflow_count=len(workflow_paths), visibility=visibility,
                error=f"Could not read workflow '{path}': {e}", branch=branch or "",
            )
        if content and matcher.search(content):
            matched_files.append(path)

    return WorkflowSearchResult(
        repo_full_name=full_name,
        repo_url=url,
        found=bool(matched_files),
        matched_files=matched_files,
        workflow_count=len(workflow_paths),
        visibility=visibility,
        branch=branch or "",
    )


def check_repo_for_trufflehog(
    github: GitHubClient,
    owner: str,
    repo: str,
    repo_url: str | None = None,
    visibility: str | None = None,
    default_branch: str | None = None,
    branch: str | None = None,
) -> PipelineCheckResult:
    """Check a single repository's GitHub Actions workflows for TruffleHog usage.

    Args:
        github: An authenticated (or public-only) GitHubClient.
        owner: Repository owner (user or org).
        repo: Repository name.
        repo_url: Optional HTML URL for display purposes.
        visibility: Repo visibility ('public', 'private', 'internal') if already known.
            If omitted, it is looked up via the GitHub API.
        default_branch: Repo's default branch, used to resolve org-ruleset-enforced
            required workflows when `branch` is not given. If omitted, it is looked
            up via the GitHub API.
        branch: Specific branch to check instead of the default branch (e.g. a
            release branch). Workflow files and effective rules are both read from
            this branch. If omitted, the repo's default branch is used.

    Returns:
        PipelineCheckResult describing whether TruffleHog was found.
    """
    full_name = f"{owner}/{repo}"
    url = repo_url or f"https://github.com/{full_name}"

    if visibility is None or default_branch is None:
        try:
            repo_data = github.get_repo_info(owner, repo)
        except GitHubAPIError as e:
            return PipelineCheckResult(
                repo_full_name=full_name,
                repo_url=url,
                has_trufflehog=False,
                visibility=visibility or "unknown",
                error=str(e),
                branch=branch or default_branch or "",
            )
        if repo_data is None:
            return PipelineCheckResult(
                repo_full_name=full_name,
                repo_url=url,
                has_trufflehog=False,
                visibility=visibility or "unknown",
                error="Repository not found or inaccessible.",
                branch=branch or default_branch or "",
            )
        if visibility is None:
            visibility = repo_data.get("visibility") or ("private" if repo_data.get("private") else "public")
        if default_branch is None:
            default_branch = repo_data.get("default_branch")

    # `branch` pins the check to a specific branch (e.g. a release branch); when it's
    # not given, `ref=None` lets GitHub resolve to the repo's default branch for us,
    # and the ruleset check below falls back to using `default_branch` instead.
    rules_branch = branch or default_branch
    effective_branch = branch or default_branch or ""

    try:
        workflow_paths = github.list_workflow_files(owner, repo, ref=branch)
    except GitHubAPIError as e:
        return PipelineCheckResult(
            repo_full_name=full_name, repo_url=url, has_trufflehog=False, visibility=visibility, error=str(e),
            branch=effective_branch,
        )

    matched_files: list[str] = []
    pr_gated_files: list[str] = []
    for path in workflow_paths:
        try:
            content = github.get_file_content(owner, repo, path, ref=branch)
        except GitHubAPIError as e:
            return PipelineCheckResult(
                repo_full_name=full_name,
                repo_url=url,
                has_trufflehog=False,
                workflow_count=len(workflow_paths),
                visibility=visibility,
                error=f"Could not read workflow '{path}': {e}",
                branch=effective_branch,
            )
        if not content:
            continue

        try:
            is_trufflehog, is_pr_eligible = _workflow_has_trufflehog(github, content, owner, repo)
        except GitHubAPIError as e:
            return PipelineCheckResult(
                repo_full_name=full_name,
                repo_url=url,
                has_trufflehog=False,
                workflow_count=len(workflow_paths),
                visibility=visibility,
                error=f"Could not read reusable workflow referenced from '{path}': {e}",
                branch=effective_branch,
            )

        if is_trufflehog:
            matched_files.append(path)
            if _workflow_triggers_on_pr(content) and is_pr_eligible:
                pr_gated_files.append(path)

    # Even with no matching workflow file in the repo itself, an org-level ruleset can
    # enforce a reusable "required workflow" (e.g. a central TruffleHog scan) on this repo.
    # GitHub always runs required workflows on pull requests, regardless of the reusable
    # workflow's own `on:` triggers, so any match here is inherently PR-gated.
    org_ruleset_enforced = False
    if rules_branch:
        required_matches = _find_required_workflow_matches(github, owner, repo, rules_branch)
        logger.debug("Repo '%s': %d required-workflow match(es) on branch '%s'",
                     full_name, len(required_matches), rules_branch)
        for match in required_matches:
            try:
                ref_content = _get_cached_workflow_content(
                    github, match.ref_owner, match.ref_repo, match.ref_path, ref=match.ref_branch
                )
            except GitHubAPIError as e:
                return PipelineCheckResult(
                    repo_full_name=full_name,
                    repo_url=url,
                    has_trufflehog=False,
                    workflow_count=len(workflow_paths),
                    visibility=visibility,
                    error=(
                        f"Could not read required workflow "
                        f"'{match.ref_owner}/{match.ref_repo}/{match.ref_path}': {e}"
                    ),
                    branch=effective_branch,
                )
            if ref_content is None:
                logger.warning("'%s' requires workflow %s/%s/%s but it could not be fetched "
                               "(private repo the token can't read, or wrong path/ref)",
                               full_name, match.ref_owner, match.ref_repo, match.ref_path)
            else:
                ref_has_trufflehog, ref_pr_eligible = _workflow_has_trufflehog(
                    github,
                    ref_content,
                    match.ref_owner,
                    match.ref_repo,
                )
                if not ref_has_trufflehog:
                    logger.debug("Required workflow %s/%s/%s does not reference TruffleHog",
                                 match.ref_owner, match.ref_repo, match.ref_path)
                    continue
                if match.is_org_ruleset:
                    org_ruleset_enforced = True
                entry = f"{match.ruleset_source} -> {match.ref_owner}/{match.ref_repo}/{match.ref_path}"
                matched_files.append(entry)
                if ref_pr_eligible:
                    pr_gated_files.append(entry)
    else:
        logger.debug("Repo '%s': no default branch known, skipping org-ruleset check", full_name)

    return PipelineCheckResult(
        repo_full_name=full_name,
        repo_url=url,
        has_trufflehog=bool(matched_files),
        matched_files=matched_files,
        pr_gated_files=pr_gated_files,
        workflow_count=len(workflow_paths),
        visibility=visibility,
        org_ruleset_enforced=org_ruleset_enforced,
        branch=effective_branch,
    )
