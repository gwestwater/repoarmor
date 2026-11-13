"""Agent that translates natural language to scanner actions."""

import json
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from ..cli.validators import validate_github_url
from ..config.settings import get_data_dir, get_settings
from ..db.database import init_database, session_scope
from ..db import queries
from ..scanner.trufflehog import scan_repository, get_repo_name_from_url, check_trufflehog_installed
from ..scanner.github_api import GitHubClient, GitHubAPIError
from ..ui.console import console
from .providers import LLMProvider


def get_memory_path() -> Path:
    """Get the path to the conversation memory file."""
    return get_data_dir() / "chat_memory.json"


def load_memory() -> list[dict]:
    """Load conversation memory from file."""
    memory_path = get_memory_path()
    if memory_path.exists():
        try:
            with open(memory_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []


def save_memory(messages: list[dict]) -> None:
    """Save conversation memory to file."""
    memory_path = get_memory_path()
    memory_path.parent.mkdir(parents=True, exist_ok=True)

    # Secure the directory
    try:
        os.chmod(memory_path.parent, stat.S_IRWXU)  # 0o700
    except OSError:
        pass

    # Filter out system messages for storage (we'll add it fresh on load)
    # Keep only user, assistant, and tool messages
    storable = [m for m in messages if m.get("role") != "system"]

    # Limit memory to last 50 exchanges to prevent unbounded growth
    max_messages = 100
    if len(storable) > max_messages:
        storable = storable[-max_messages:]

    with open(memory_path, "w") as f:
        json.dump(storable, f, indent=2)

    # Secure the memory file (may contain sensitive scan info)
    try:
        os.chmod(memory_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except OSError:
        pass


SYSTEM_PROMPT = """You are an assistant that helps manage secret scanning results. You have access to tools to:

1. Scan GitHub repositories for secrets (individual repos or entire organizations)
2. List scanned repositories
3. View and filter findings
4. Get statistics

When users ask questions or give commands, use the appropriate tools to help them. Be concise in responses.

Guidelines:
- For scanning individual repos, use scan_repository with the repo URL
- For scanning organizations, use scan_organization with the org name (requires GITHUB_TOKEN env var)
- When showing findings, summarize the key information
- If a query is ambiguous, ask for clarification
- Present data in a clear, readable format
"""


TOOLS = [
    {
        "name": "scan_repository",
        "description": "Scan a GitHub repository for secrets using TruffleHog. Returns the number of findings.",
        "parameters": {
            "type": "object",
            "properties": {
                "repo_url": {
                    "type": "string",
                    "description": "GitHub repository URL (e.g., https://github.com/owner/repo)",
                },
                "depth": {
                    "type": "integer",
                    "description": "Number of commits to scan (default: 50)",
                },
            },
            "required": ["repo_url"],
        },
    },
    {
        "name": "scan_organization",
        "description": "Scan all repositories in a GitHub organization for secrets. Requires GITHUB_TOKEN environment variable to be set.",
        "parameters": {
            "type": "object",
            "properties": {
                "org_name": {
                    "type": "string",
                    "description": "GitHub organization name (e.g., 'anthropic', 'trufflesecurity')",
                },
                "include_private": {
                    "type": "boolean",
                    "description": "Include private repositories (default: true)",
                },
                "include_archived": {
                    "type": "boolean",
                    "description": "Include archived repositories (default: false)",
                },
                "depth": {
                    "type": "integer",
                    "description": "Number of commits to scan per repo (default: 50)",
                },
            },
            "required": ["org_name"],
        },
    },
    {
        "name": "list_repositories",
        "description": "List all scanned repositories with their scan dates and finding counts.",
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "get_findings",
        "description": "Get secret findings with optional filters. Returns finding details. Default limit is 25 to stay within token limits.",
        "parameters": {
            "type": "object",
            "properties": {
                "repo_name": {
                    "type": "string",
                    "description": "Filter by repository name (partial match)",
                },
                "detector_type": {
                    "type": "string",
                    "description": "Filter by detector type (e.g., AWS, PrivateKey)",
                },
                "verified_only": {
                    "type": "boolean",
                    "description": "If true, only return findings verified by TruffleHog as active",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum findings to return (default: 25, max: 100)",
                },
            },
        },
    },
    {
        "name": "get_finding_detail",
        "description": "Get detailed information about a specific finding by ID.",
        "parameters": {
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "integer",
                    "description": "The finding ID",
                },
            },
            "required": ["finding_id"],
        },
    },
    {
        "name": "get_statistics",
        "description": "Get summary statistics about findings (counts by type, organization, repository).",
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
]


class RepoArmorAgent:
    """Agent that executes scanner commands via LLM."""

    def __init__(self, provider: LLMProvider, load_history: bool = True):
        self.provider = provider
        self.settings = get_settings()
        init_database(self.settings.database.path)

        # Initialize with system prompt
        self.messages: list[dict] = [
            {"role": "system", "content": SYSTEM_PROMPT}
        ]

        # Load previous conversation history if available
        if load_history:
            stored_messages = load_memory()
            if stored_messages:
                self.messages.extend(stored_messages)
                console.print(f"[muted]Loaded {len(stored_messages)} messages from history. Use 'clear' to reset.[/muted]")

    def _validate_tool_args(self, name: str, arguments: dict) -> str | None:
        """Validate tool arguments. Returns error message if invalid, None if valid."""
        # Basic type and range validation for known parameters
        if "depth" in arguments:
            depth = arguments.get("depth")
            if depth is not None:
                if not isinstance(depth, int) or depth < 1 or depth > 10000:
                    return "depth must be an integer between 1 and 10000"

        if "limit" in arguments:
            limit = arguments.get("limit")
            if limit is not None:
                if not isinstance(limit, int) or limit < 1 or limit > 100:
                    return "limit must be an integer between 1 and 100"

        if "finding_id" in arguments:
            fid = arguments.get("finding_id")
            if not isinstance(fid, int) or fid < 1:
                return "finding_id must be a positive integer"

        if "finding_ids" in arguments:
            fids = arguments.get("finding_ids")
            if not isinstance(fids, list) or not all(isinstance(i, int) and i > 0 for i in fids):
                return "finding_ids must be a list of positive integers"

        if "repo_url" in arguments:
            url = arguments.get("repo_url")
            if url and not isinstance(url, str):
                return "repo_url must be a string"
            if url:
                # Use the same validation as CLI for security
                try:
                    validate_github_url(url)
                except ValueError as e:
                    return str(e)

        if "org_name" in arguments:
            org = arguments.get("org_name")
            if not isinstance(org, str) or len(org) < 1:
                return "org_name must be a non-empty string"

        return None

    def _execute_tool(self, name: str, arguments: dict) -> str:
        """Execute a tool and return the result as a string."""
        # Validate arguments before execution
        validation_error = self._validate_tool_args(name, arguments)
        if validation_error:
            return f"Invalid arguments for {name}: {validation_error}"

        try:
            if name == "scan_repository":
                return self._scan_repository(**arguments)
            elif name == "scan_organization":
                return self._scan_organization(**arguments)
            elif name == "list_repositories":
                return self._list_repositories()
            elif name == "get_findings":
                return self._get_findings(**arguments)
            elif name == "get_finding_detail":
                return self._get_finding_detail(**arguments)
            elif name == "get_statistics":
                return self._get_statistics()
            else:
                return f"Unknown tool: {name}"
        except Exception as e:
            return f"Error executing {name}: {str(e)}"

    def _scan_repository(self, repo_url: str, depth: int = 50) -> str:
        """Scan a repository for secrets."""
        try:
            check_trufflehog_installed(self.settings.scanner.trufflehog_path)
        except Exception as e:
            return str(e)

        repo_name = get_repo_name_from_url(repo_url)

        with session_scope() as session:
            # Get or create repository
            repo = queries.get_repository_by_url(session, repo_url)
            if not repo:
                repo = queries.create_repository(session, repo_url, repo_name)

            # Get existing hashes for dedup
            existing_hashes = {
                f.secret_hash for f in queries.get_findings_by_repo(session, repo.id)
            }

            findings_count = 0
            new_count = 0

            for result in scan_repository(repo_url, depth=depth, settings=self.settings):
                findings_count += 1
                if result.secret_hash not in existing_hashes:
                    queries.create_finding(
                        session,
                        repo_id=repo.id,
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
                    existing_hashes.add(result.secret_hash)
                    new_count += 1

            queries.update_repository_stats(session, repo)

        return f"Scanned {repo_name}: found {findings_count} total secrets, {new_count} new."

    def _scan_organization(
        self,
        org_name: str,
        include_private: bool = True,
        include_archived: bool = False,
        depth: int = 50,
    ) -> str:
        """Scan all repositories in a GitHub organization."""
        try:
            check_trufflehog_installed(self.settings.scanner.trufflehog_path)
        except Exception as e:
            return str(e)

        # Initialize GitHub client
        try:
            github = GitHubClient()
        except GitHubAPIError as e:
            return str(e)

        # Validate org access
        if not github.validate_org_access(org_name):
            return f"Cannot access organization: {org_name}. Check the org name and token permissions."

        # Get repos
        try:
            repos = list(github.get_org_repos(
                org_name,
                include_private=include_private,
                include_archived=include_archived,
            ))
        except GitHubAPIError as e:
            return str(e)

        if not repos:
            return f"No repositories found in organization: {org_name}"

        # Scan each repo
        total_findings = 0
        total_new = 0
        scanned = 0
        errors = []

        for gh_repo in repos:
            try:
                repo_url = gh_repo.url
                repo_name = gh_repo.full_name

                with session_scope() as session:
                    repo = queries.get_repository_by_url(session, repo_url)
                    if not repo:
                        repo = queries.create_repository(session, repo_url, repo_name, gh_repo.visibility)
                    elif repo.visibility != gh_repo.visibility:
                        repo.visibility = gh_repo.visibility

                    existing_hashes = {
                        f.secret_hash for f in queries.get_findings_by_repo(session, repo.id)
                    }

                    findings_count = 0
                    new_count = 0

                    for result in scan_repository(repo_url, depth=depth, settings=self.settings):
                        findings_count += 1
                        if result.secret_hash not in existing_hashes:
                            queries.create_finding(
                                session,
                                repo_id=repo.id,
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
                            existing_hashes.add(result.secret_hash)
                            new_count += 1

                    queries.update_repository_stats(session, repo)

                total_findings += findings_count
                total_new += new_count
                scanned += 1

            except Exception as e:
                errors.append(f"{gh_repo.name}: {str(e)}")

        result = f"Scanned {scanned}/{len(repos)} repos in {org_name}: {total_findings} total secrets, {total_new} new."
        if errors:
            result += f"\nErrors ({len(errors)}): " + "; ".join(errors[:3])
            if len(errors) > 3:
                result += f" ... and {len(errors) - 3} more"

        return result

    def _list_repositories(self) -> str:
        """List all repositories."""
        with session_scope() as session:
            repos = queries.get_all_repositories(session)
            if not repos:
                return "No repositories have been scanned yet."

            lines = ["Scanned repositories:"]
            for repo in repos:
                last_scan = repo.last_scanned.strftime("%Y-%m-%d") if repo.last_scanned else "Never"
                lines.append(
                    f"- {repo.name} ({repo.visibility}): {repo.total_findings} findings, "
                    f"last scan: {last_scan}"
                )
            return "\n".join(lines)

    def _get_findings(
        self,
        repo_name: str | None = None,
        detector_type: str | None = None,
        verified_only: bool | None = None,
        limit: int | None = None,
    ) -> str:
        """Get findings with filters."""
        # Apply default limit of 25, max 100 to stay within token limits
        effective_limit = min(limit or 25, 100)

        with session_scope() as session:
            # Resolve repo filter
            repo_id = None
            if repo_name:
                repos = queries.get_all_repositories(session)
                for r in repos:
                    if repo_name.lower() in r.name.lower():
                        repo_id = r.id
                        break

            # Get total count for pagination info
            total_count = queries.get_filtered_findings_count(
                session,
                repo_id=repo_id,
                detector_type=detector_type,
                verified_by_trufflehog=verified_only,
            )

            findings = queries.get_findings(
                session,
                repo_id=repo_id,
                detector_type=detector_type,
                verified_by_trufflehog=verified_only,
                limit=effective_limit,
            )

            if not findings:
                return "No findings match the criteria."

            lines = [f"Showing {len(findings)} of {total_count} findings:"]

            for f in findings:
                repo = f.repository.name if f.repository else "unknown"
                visibility = f.repository.visibility if f.repository else "public"
                # Truncate long file paths to save tokens
                file_path = f.file_path
                if len(file_path) > 50:
                    file_path = "..." + file_path[-47:]
                verified_marker = "✓" if f.verified_by_trufflehog else ""
                lines.append(
                    f"- #{f.id} {f.detector_type} in {repo} ({visibility}) "
                    f"({file_path}:{f.line_number or '?'}) {verified_marker}"
                )

            if total_count > effective_limit:
                lines.append(f"\n({total_count - effective_limit} more not shown. Use limit parameter for more.)")

            return "\n".join(lines)

    def _get_finding_detail(self, finding_id: int) -> str:
        """Get detailed finding info."""
        with session_scope() as session:
            finding = queries.get_finding_by_id(session, finding_id)
            if not finding:
                return f"Finding #{finding_id} not found."

            repo_name = finding.repository.name if finding.repository else 'unknown'
            visibility = finding.repository.visibility if finding.repository else "public"

            lines = [
                f"Finding #{finding.id}:",
                f"  Repository: {repo_name} ({visibility})",
                f"  Type: {finding.detector_type}",
                f"  File: {finding.file_path}:{finding.line_number or '?'}",
                f"  Commit: {finding.commit[:8] if finding.commit else 'N/A'}",
            ]
            if finding.redacted_secret:
                lines.append(f"  Secret (redacted): {finding.redacted_secret}")
            if finding.verified_by_trufflehog:
                lines.append("  ⚠️ Verified active by TruffleHog")

            return "\n".join(lines)

    def _get_statistics(self) -> str:
        """Get summary statistics."""
        with session_scope() as session:
            total_repos = queries.get_total_repos_count(session)
            total_findings = queries.get_total_findings_count(session)
            by_type = queries.get_findings_count_by_type(session)
            by_org = queries.get_findings_count_by_org(session, limit=5)
            by_repo = queries.get_findings_count_by_repo(session, limit=5)

            lines = [
                "Statistics:",
                f"  Repositories: {total_repos}",
                f"  Total findings: {total_findings}",
            ]

            if by_org:
                lines.append("")
                lines.append("  By organization:")
                for org, count in by_org.items():
                    lines.append(f"    {org}: {count}")

            if by_repo:
                lines.append("")
                lines.append("  Top repositories:")
                for repo, count in by_repo.items():
                    lines.append(f"    {repo}: {count}")

            if by_type:
                lines.append("")
                lines.append("  Top types:")
                for dtype, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:5]:
                    lines.append(f"    {dtype}: {count}")

            return "\n".join(lines)

    def chat(self, user_message: str) -> str:
        """Process a user message and return a response."""
        self.messages.append({"role": "user", "content": user_message})

        # Get LLM response
        response = self.provider.chat(self.messages, tools=TOOLS)

        # Process tool calls if any
        while response.get("tool_calls"):
            # Add assistant message with tool calls
            # Format tool_calls for OpenAI compatibility
            formatted_tool_calls = []
            for tc in response["tool_calls"]:
                formatted_tool_calls.append({
                    "id": tc["id"],
                    "type": "function",
                    "function": {
                        "name": tc["name"],
                        "arguments": json.dumps(tc["arguments"]) if isinstance(tc["arguments"], dict) else tc["arguments"],
                    },
                })

            self.messages.append({
                "role": "assistant",
                "content": response.get("content", "") or None,
                "tool_calls": formatted_tool_calls,
            })

            # Execute each tool and collect results
            for tool_call in response["tool_calls"]:
                tool_id = tool_call["id"]
                tool_name = tool_call["name"]
                tool_args = tool_call["arguments"]

                console.print(f"[muted]Executing: {tool_name}...[/muted]")
                result = self._execute_tool(tool_name, tool_args)

                # Add tool result to messages (OpenAI format)
                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tool_id,
                    "content": result,
                })

            # Get next response
            response = self.provider.chat(self.messages, tools=TOOLS)

        # Add final assistant response
        final_response = response.get("content", "")
        self.messages.append({"role": "assistant", "content": final_response})

        # Save conversation to memory
        save_memory(self.messages)

        return final_response

    def reset_conversation(self) -> None:
        """Reset conversation history and clear saved memory."""
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        # Clear the memory file
        save_memory([])
