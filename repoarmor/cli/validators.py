"""Input validation utilities."""

import re
from pathlib import Path


def validate_repo_url(url: str) -> str:
    """Validate and normalize a repository URL (GitHub, Azure DevOps, Bitbucket, or local path).

    Args:
        url: The URL or local filesystem path to validate.

    Returns:
        Normalized URL or absolute local path.

    Raises:
        ValueError: If URL/path is invalid.
    """
    url = url.strip()

    # Local filesystem path (absolute, relative, file:// URL, or a bare relative
    # path - with or without a leading "./" - that exists as a git repo on disk)
    looks_like_remote = bool(re.match(r"^(https?://|[\w\-\.]+@[^/:]+:)", url, re.IGNORECASE))
    try:
        is_bare_relative_repo = not looks_like_remote and (Path(url).expanduser() / ".git").exists()
    except OSError:
        is_bare_relative_repo = False
    if (
        url.startswith("file://")
        or url.startswith("/")
        or url.startswith("./")
        or url.startswith("../")
        or url.startswith("~")
        or is_bare_relative_repo
    ):
        # Strip file:// prefix if present
        path_str = url[7:] if url.startswith("file://") else url
        path = Path(path_str).expanduser().resolve()

        if not path.exists():
            raise ValueError(f"Local path does not exist: {path}")
        if not path.is_dir():
            raise ValueError(f"Local path is not a directory: {path}")

        # Check if it's a git repo (.git directory or file)
        if not (path / ".git").exists():
            raise ValueError(f"Local path is not a git repository (no .git): {path}")

        return str(path)

    # GitHub patterns
    github_patterns = [
        r"^https?://github\.com/[\w\-\.]+/[\w\-\.]+(?:\.git)?/?$",
        r"^git@github\.com:[\w\-\.]+/[\w\-\.]+(?:\.git)?$",
        r"^github\.com/[\w\-\.]+/[\w\-\.]+(?:\.git)?/?$",
    ]

    for pattern in github_patterns:
        if re.match(pattern, url, re.IGNORECASE):
            if url.startswith("git@"):
                url = url.replace("git@github.com:", "https://github.com/")
            elif not url.startswith(("http://", "https://")):
                url = "https://" + url
            url = url.rstrip("/")
            if url.endswith(".git"):
                url = url[:-4]
            return url

    # Azure DevOps patterns
    azure_patterns = [
        # https://dev.azure.com/org/project/_git/repo
        r"^https?://dev\.azure\.com/[\w\-\.]+/[\w\-\.%]+/_git/[\w\-\.]+(?:\.git)?/?$",
        # https://org@dev.azure.com/org/project/_git/repo
        r"^https?://[\w\-\.]+@dev\.azure\.com/[\w\-\.]+/[\w\-\.%]+/_git/[\w\-\.]+(?:\.git)?/?$",
        # https://org.visualstudio.com/project/_git/repo (legacy)
        r"^https?://[\w\-\.]+\.visualstudio\.com/[\w\-\.%]+/_git/[\w\-\.]+(?:\.git)?/?$",
        # SSH: git@ssh.dev.azure.com:v3/org/project/repo
        r"^git@ssh\.dev\.azure\.com:v3/[\w\-\.]+/[\w\-\.%]+/[\w\-\.]+$",
    ]

    for pattern in azure_patterns:
        if re.match(pattern, url, re.IGNORECASE):
            url = url.rstrip("/")
            if url.endswith(".git"):
                url = url[:-4]
            return url

    # Bitbucket patterns
    bitbucket_patterns = [
        # https://bitbucket.org/owner/repo
        r"^https?://bitbucket\.org/[\w\-\.]+/[\w\-\.]+(?:\.git)?/?$",
        # git@bitbucket.org:owner/repo.git
        r"^git@bitbucket\.org:[\w\-\.]+/[\w\-\.]+(?:\.git)?$",
        # bitbucket.org/owner/repo (no protocol)
        r"^bitbucket\.org/[\w\-\.]+/[\w\-\.]+(?:\.git)?/?$",
    ]

    for pattern in bitbucket_patterns:
        if re.match(pattern, url, re.IGNORECASE):
            if url.startswith("git@"):
                url = url.replace("git@bitbucket.org:", "https://bitbucket.org/")
            elif not url.startswith(("http://", "https://")):
                url = "https://" + url
            url = url.rstrip("/")
            if url.endswith(".git"):
                url = url[:-4]
            return url

    # Bitbucket Server/Data Center (self-hosted) patterns
    # Clone URL: https://hostname/scm/PROJECT/repo.git
    bb_server_scm_pattern = r"^https?://[\w\-\.]+(?::\d+)?/scm/[\w\-\.]+/[\w\-\.]+(?:\.git)?/?$"
    if re.match(bb_server_scm_pattern, url, re.IGNORECASE):
        url = url.rstrip("/")
        if url.endswith(".git"):
            url = url[:-4]
        return url

    # Web UI: https://hostname/projects/PROJECT/repos/repo/browse (convert to clone URL)
    bb_server_web_pattern = r"^https?://[\w\-\.]+(?::\d+)?/projects/([\w\-\.]+)/repos/([\w\-\.]+)(?:/browse)?/?$"
    match = re.match(bb_server_web_pattern, url, re.IGNORECASE)
    if match:
        # Extract base URL and convert to clone URL format
        parsed = url.split("/projects/")[0]
        project = match.group(1)
        repo = match.group(2)
        return f"{parsed}/scm/{project}/{repo}"

    raise ValueError(
        f"Invalid repository URL: {url}\n"
        "Supported formats:\n"
        "  GitHub:           https://github.com/owner/repo\n"
        "  Azure DevOps:     https://dev.azure.com/org/project/_git/repo\n"
        "  Bitbucket Cloud:  https://bitbucket.org/owner/repo\n"
        "  Bitbucket Server: https://your-server.com/scm/PROJECT/repo\n"
        "  Local path:       /path/to/cloned/repo (or ./repo, ~/repo, file:///path)"
    )


# Keep backward-compatible alias
validate_github_url = validate_repo_url


def validate_batch_file(file_path: str) -> list[str]:
    """Validate and read URLs from a batch file.

    Args:
        file_path: Path to file containing URLs.

    Returns:
        List of validated URLs.

    Raises:
        ValueError: If file is invalid or contains invalid URLs.
    """
    path = Path(file_path)

    if not path.exists():
        raise ValueError(f"File not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Not a file: {file_path}")

    urls = []
    errors = []

    with open(path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            try:
                validated_url = validate_repo_url(line)
                urls.append(validated_url)
            except ValueError as e:
                errors.append(f"Line {line_num}: {e}")

    if errors:
        error_msg = "Invalid URLs in batch file:\n" + "\n".join(errors)
        raise ValueError(error_msg)

    if not urls:
        raise ValueError("Batch file contains no valid URLs")

    return urls


def validate_finding_ids(ids_str: str) -> list[int]:
    """Parse and validate a comma-separated list of finding IDs.

    Args:
        ids_str: Comma-separated string of IDs (e.g., "1,2,3" or "1-5,7,9").

    Returns:
        List of integer IDs.

    Raises:
        ValueError: If any ID is invalid.
    """
    ids = set()

    for part in ids_str.split(","):
        part = part.strip()

        if "-" in part:
            # Range like "1-5"
            try:
                start, end = part.split("-")
                start_id = int(start.strip())
                end_id = int(end.strip())

                if start_id > end_id:
                    raise ValueError(f"Invalid range: {part}")

                ids.update(range(start_id, end_id + 1))
            except (ValueError, AttributeError):
                raise ValueError(f"Invalid ID range: {part}")
        else:
            # Single ID
            try:
                ids.add(int(part))
            except ValueError:
                raise ValueError(f"Invalid finding ID: {part}")

    return sorted(ids)
