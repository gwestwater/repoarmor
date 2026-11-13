"""TruffleHog wrapper for running scans."""

import hashlib
import json
import logging
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Generator

from ..config.settings import Settings, get_settings

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Parsed result from TruffleHog scan."""
    detector_type: str
    decoder_type: str | None
    file_path: str
    line_number: int | None
    commit: str | None
    author: str | None
    author_email: str | None
    commit_date: datetime | None
    message: str | None
    secret_hash: str
    redacted_secret: str | None
    verified_by_trufflehog: bool
    raw_finding: str


class TruffleHogError(Exception):
    """Exception raised for TruffleHog errors."""
    pass


class TruffleHogNotFoundError(TruffleHogError):
    """Exception raised when TruffleHog is not installed."""
    pass


def check_trufflehog_installed(trufflehog_path: str = "trufflehog") -> str:
    """Check if TruffleHog is installed and return its version.

    Args:
        trufflehog_path: Path to TruffleHog binary.

    Returns:
        TruffleHog version string.

    Raises:
        TruffleHogNotFoundError: If TruffleHog is not found.
    """
    # Check if trufflehog exists
    if not shutil.which(trufflehog_path):
        raise TruffleHogNotFoundError(
            f"TruffleHog not found at '{trufflehog_path}'. "
            "Please install it: https://github.com/trufflesecurity/trufflehog#installation"
        )

    try:
        result = subprocess.run(
            [trufflehog_path, "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        version = result.stdout.strip() or result.stderr.strip()
        logger.debug(f"TruffleHog version: {version}")
        return version
    except subprocess.TimeoutExpired:
        raise TruffleHogError("TruffleHog version check timed out")
    except Exception as e:
        raise TruffleHogError(f"Error checking TruffleHog version: {e}")


def _hash_secret(secret: str) -> str:
    """Create a hash of the secret for deduplication."""
    return hashlib.sha256(secret.encode()).hexdigest()


def _redact_secret(secret: str, visible_chars: int = 4) -> str:
    """Redact a secret, showing only first and last few characters."""
    if len(secret) <= visible_chars * 2:
        return "*" * len(secret)
    return f"{secret[:visible_chars]}...{secret[-visible_chars:]}"


def _sanitize_stderr(text: str) -> str:
    """Remove credentials from URLs in stderr output before logging.

    TruffleHog or Git may echo the authenticated URL (e.g.
    ``https://x-access-token:<token>@github.com/...``) into stderr on
    failure.  This function replaces the ``user:password@`` portion of any
    such URL with ``[REDACTED]@`` so tokens are never written to logs or
    persisted scan history.
    """
    return re.sub(r"(https?://)([^/@\s]+:[^/@\s]+@)", r"\1[REDACTED]@", text)


def _parse_timestamp(timestamp_str: str | None) -> datetime | None:
    """Parse a timestamp string from TruffleHog."""
    if not timestamp_str:
        return None

    # TruffleHog outputs ISO 8601 format
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str.replace("+00:00", "Z"), fmt)
        except ValueError:
            continue

    logger.debug(f"Could not parse timestamp: {timestamp_str}")
    return None


def _parse_finding(finding_json: dict) -> ScanResult:
    """Parse a single finding from TruffleHog JSON output.

    Args:
        finding_json: Parsed JSON object from TruffleHog.

    Returns:
        Parsed ScanResult.
    """
    # Extract detector info - prefer DetectorName (human-readable) over DetectorType (numeric ID)
    detector_name = finding_json.get("DetectorName", finding_json.get("detectorName"))
    detector_type_id = finding_json.get("DetectorType", finding_json.get("detectorType"))
    detector_type = detector_name or str(detector_type_id) if detector_type_id else "Unknown"
    decoder_name = finding_json.get("DecoderName", finding_json.get("decoderName"))
    decoder_type = decoder_name or finding_json.get("DecoderType", finding_json.get("decoderType"))

    # Extract source metadata (varies by source type)
    source_metadata = finding_json.get("SourceMetadata", finding_json.get("sourceMetadata", {}))
    data = source_metadata.get("Data", source_metadata.get("data", {}))

    # Handle different source types (Git, GitHub, etc.)
    git_data = data.get("Git", data.get("git", data.get("Github", data.get("github", {}))))

    file_path = git_data.get("file", data.get("file", "unknown"))
    line_number = git_data.get("line", data.get("line"))
    commit = git_data.get("commit", data.get("commit"))
    author = git_data.get("email", data.get("email"))  # TruffleHog puts email in "email" field
    author_email = git_data.get("email", data.get("email"))
    timestamp = git_data.get("timestamp", data.get("timestamp"))
    commit_date = _parse_timestamp(timestamp)

    # Get commit message if available
    message = git_data.get("message", data.get("message"))

    # Extract the raw secret and create hash
    raw_secret = finding_json.get("Raw", finding_json.get("raw", ""))
    secret_hash = _hash_secret(raw_secret) if raw_secret else ""
    # Use TruffleHog's redacted version if available, otherwise compute our own
    redacted_secret = finding_json.get("Redacted", finding_json.get("redacted"))
    if not redacted_secret and raw_secret:
        redacted_secret = _redact_secret(raw_secret)

    # Check if verified by TruffleHog
    verified = finding_json.get("Verified", finding_json.get("verified", False))

    return ScanResult(
        detector_type=str(detector_type),
        decoder_type=str(decoder_type) if decoder_type else None,
        file_path=str(file_path),
        line_number=int(line_number) if line_number else None,
        commit=str(commit) if commit else None,
        author=str(author) if author else None,
        author_email=str(author_email) if author_email else None,
        commit_date=commit_date,
        message=str(message)[:500] if message else None,  # Truncate long messages
        secret_hash=secret_hash,
        redacted_secret=redacted_secret,
        verified_by_trufflehog=bool(verified),
        raw_finding=json.dumps(finding_json),
    )


def scan_repository(
    repo_url: str,
    depth: int | None = None,
    branch: str | None = None,
    only_verified: bool = False,
    timeout: int | None = None,
    settings: Settings | None = None,
) -> Generator[ScanResult, None, None]:
    """Scan a GitHub repository for secrets.

    Args:
        repo_url: URL of the GitHub repository.
        depth: Number of commits to scan (None for all).
        branch: Specific branch to scan (None for default).
        only_verified: Only return findings verified by TruffleHog.
        timeout: Timeout in seconds.
        settings: Settings object.

    Yields:
        ScanResult objects for each finding.

    Raises:
        TruffleHogError: If the scan fails.
    """
    if settings is None:
        settings = get_settings()

    trufflehog_path = settings.scanner.trufflehog_path

    # TruffleHog requires file:// prefix for local paths
    scan_target = repo_url
    if not scan_target.startswith("file://"):
        local_repo_path = Path(scan_target).expanduser()
        if local_repo_path.exists() and local_repo_path.is_dir():
            scan_target = local_repo_path.resolve().as_uri()

    # Build command
    cmd = [
        trufflehog_path,
        "git",
        scan_target,
        "--json",
        "--no-update",
        "--bare",  # Use bare clone for faster scanning
    ]

    if only_verified:
        cmd.append("--only-verified")

    if depth:
        cmd.extend(["--max-depth", str(depth)])

    if branch:
        cmd.extend(["--branch", branch])

    effective_timeout = timeout or settings.scanner.timeout

    # Sanitize command for logging (redact any tokens in URLs)
    safe_cmd = []
    for c in cmd:
        if "://" in c and "@" in c.split("://")[1].split("/")[0]:
            # Redact any authenticated URL (any provider, including self-hosted)
            safe_cmd.append("[REDACTED_AUTH_URL]")
        else:
            safe_cmd.append(c)
    logger.info(f"Running scan: {' '.join(safe_cmd)}")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Drain stderr in a background thread to prevent pipe buffer deadlock.
        # On Windows the pipe buffer is ~4KB (vs ~64KB on macOS/Linux), so
        # TruffleHog blocks when it tries to write progress output to stderr
        # while this thread is blocked reading stdout — causing an infinite hang.
        from collections import deque

        stderr_lines = deque(maxlen=2000)
        stderr_lock = threading.Lock()

        def _drain_stderr() -> None:
            try:
                if process.stderr is None:
                    return
                for line in process.stderr:
                    with stderr_lock:
                        stderr_lines.append(line)
            except Exception as e:
                with stderr_lock:
                    stderr_lines.append(f"[stderr drain failed: {e}]\n")

        stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
        stderr_thread.start()

        # Read output line by line (TruffleHog outputs one JSON per line)
        seen_hashes: set[str] = set()

        for line in process.stdout:
            line = line.strip()
            if not line:
                continue

            try:
                finding_json = json.loads(line)

                # Skip log/info messages from TruffleHog (they have a "level" field)
                if "level" in finding_json or "logger" in finding_json:
                    continue

                # Skip if this doesn't look like a finding (no SourceMetadata)
                if "SourceMetadata" not in finding_json and "sourceMetadata" not in finding_json:
                    continue

                result = _parse_finding(finding_json)

                # Deduplicate by secret hash
                if result.secret_hash and result.secret_hash in seen_hashes:
                    logger.debug(f"Skipping duplicate finding: {result.secret_hash[:8]}...")
                    continue

                seen_hashes.add(result.secret_hash)
                yield result

            except json.JSONDecodeError as e:
                logger.warning(f"Could not parse TruffleHog output: {e}")
                continue
            except Exception as e:
                logger.warning(f"Error processing finding: {e}")
                continue

        # Wait for process and stderr drain to complete
        process.wait(timeout=effective_timeout)
        stderr_thread.join(timeout=5)
        if stderr_thread.is_alive():
            logger.warning("Timed out waiting for stderr drain thread; stderr output may be truncated")

        if process.returncode != 0:
            stderr = _sanitize_stderr("".join(stderr_lines))
            raise TruffleHogError(
                f"TruffleHog exited with code {process.returncode}: {stderr.strip()}"
            )

    except subprocess.TimeoutExpired:
        process.kill()
        raise TruffleHogError(f"Scan timed out after {effective_timeout} seconds")
    except Exception as e:
        raise TruffleHogError(f"Scan failed: {e}")


def scan_docker_image(
    image: str,
    only_verified: bool = False,
    timeout: int | None = None,
    settings: Settings | None = None,
) -> Generator[ScanResult, None, None]:
    """Scan a Docker image for secrets using TruffleHog.

    Uses local Docker credentials for private registries (run `docker login` first).

    Args:
        image: Docker image reference (e.g. nginx:latest, registry.example.com/app:v1).
        only_verified: Only return findings verified by TruffleHog.
        timeout: Timeout in seconds.
        settings: Settings object.

    Yields:
        ScanResult objects for each finding.
    """
    if settings is None:
        settings = get_settings()

    trufflehog_path = settings.scanner.trufflehog_path

    cmd = [
        trufflehog_path,
        "docker",
        "--image", image,
        "--json",
        "--no-update",
    ]

    if only_verified:
        cmd.append("--only-verified")

    effective_timeout = timeout or settings.scanner.timeout

    logger.info(f"Scanning Docker image: {image}")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        import time
        from collections import deque
        from queue import Empty, Full, Queue
        stderr_lines: deque = deque(maxlen=2000)
        stderr_lock = threading.Lock()
        stop_stdout_drain = threading.Event()

        def _drain_stderr() -> None:
            try:
                if process.stderr is None:
                    return
                for line in process.stderr:
                    with stderr_lock:
                        stderr_lines.append(line)
            except Exception as e:
                with stderr_lock:
                    stderr_lines.append(f"[stderr drain failed: {e}]\n")

        stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
        stderr_thread.start()

        stdout_queue: Queue[str | None] = Queue(maxsize=1000)

        def _drain_stdout() -> None:
            try:
                if process.stdout is None:
                    return
                for stdout_line in process.stdout:
                    while True:
                        try:
                            stdout_queue.put(stdout_line, timeout=0.1)
                            break
                        except Full:
                            if stop_stdout_drain.is_set():
                                return
            finally:
                while not stop_stdout_drain.is_set():
                    try:
                        stdout_queue.put(None, timeout=0.1)
                        return
                    except Full:
                        continue
                try:
                    stdout_queue.put_nowait(None)
                except Full:
                    pass

        stdout_thread = threading.Thread(target=_drain_stdout, daemon=True)
        stdout_thread.start()

        seen_hashes: set[str] = set()
        deadline = time.monotonic() + effective_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(cmd, effective_timeout)
            try:
                line = stdout_queue.get(timeout=remaining)
            except Empty:
                raise subprocess.TimeoutExpired(cmd, effective_timeout)
            if line is None:
                break
            line = line.strip()
            if not line:
                continue
            try:
                finding_json = json.loads(line)
                if "level" in finding_json or "logger" in finding_json:
                    continue
                if "SourceMetadata" not in finding_json and "sourceMetadata" not in finding_json:
                    continue
                result = _parse_finding(finding_json)
                if result.secret_hash and result.secret_hash in seen_hashes:
                    continue
                seen_hashes.add(result.secret_hash)
                yield result
            except json.JSONDecodeError:
                continue
            except Exception as e:
                logger.warning(f"Error processing finding: {e}")
                continue

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(cmd, effective_timeout)
        process.wait(timeout=remaining)
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

        if process.returncode != 0:
            stderr = _sanitize_stderr("".join(stderr_lines))
            raise TruffleHogError(
                f"TruffleHog exited with code {process.returncode}: {stderr.strip()}"
            )

    except subprocess.TimeoutExpired:
        stop_stdout_drain.set()
        process.kill()
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        raise TruffleHogError(f"Docker scan timed out after {effective_timeout} seconds")
    except Exception as e:
        raise TruffleHogError(f"Docker scan failed: {e}")


def get_repo_name_from_url(url: str) -> str:
    """Extract repository name from a repository URL or local path.

    Supports GitHub, Azure DevOps, Bitbucket URL formats, and local filesystem paths.
    For local paths, attempts to use the git remote URL to derive the canonical name,
    falling back to 'local/<dirname>'.

    Args:
        url: Repository URL or absolute local filesystem path.

    Returns:
        Repository name in 'owner/repo' format (GitHub, Bitbucket)
        or 'org/project/repo' format (Azure DevOps).
        For local paths without remote: 'local/<dirname>'.
    """
    # Local filesystem path - try git remote first, fall back to dirname
    if url.startswith("/") and Path(url).exists() and Path(url).is_dir():
        try:
            result = subprocess.run(
                ["git", "-C", url, "config", "--get", "remote.origin.url"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                remote_url = result.stdout.strip()
                # Recursively resolve the remote URL to a canonical name
                return get_repo_name_from_url(remote_url)
        except (subprocess.TimeoutExpired, Exception) as e:
            logger.debug(f"Could not get git remote for {url}: {e}")
        # Fall back to directory name
        return f"local/{Path(url).name}"

    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    # Azure DevOps: https://dev.azure.com/org/project/_git/repo
    if "dev.azure.com" in url or "visualstudio.com" in url:
        # Strip user@ prefix if present (e.g. org@dev.azure.com)
        url = re.sub(r"https?://[\w\-\.]+@", "https://", url)

        parts = url.split("/")
        if "dev.azure.com" in parts:
            idx = parts.index("dev.azure.com")
            # dev.azure.com/org/project/_git/repo
            if len(parts) > idx + 4 and parts[idx + 2 + 1] == "_git":
                return f"{parts[idx + 1]}/{parts[idx + 2]}/{parts[idx + 4]}"
        elif any("visualstudio.com" in p for p in parts):
            # org.visualstudio.com/project/_git/repo
            vs_idx = next(i for i, p in enumerate(parts) if "visualstudio.com" in p)
            org = parts[vs_idx].split(".")[0]
            if len(parts) > vs_idx + 3 and parts[vs_idx + 2] == "_git":
                return f"{org}/{parts[vs_idx + 1]}/{parts[vs_idx + 3]}"

    # Azure DevOps SSH: git@ssh.dev.azure.com:v3/org/project/repo
    if "ssh.dev.azure.com" in url:
        match = re.search(r"v3/([\w\-\.]+)/([\w\-\.%]+)/([\w\-\.]+)$", url)
        if match:
            return f"{match.group(1)}/{match.group(2)}/{match.group(3)}"

    # Bitbucket Server: https://hostname/scm/PROJECT/repo
    if "/scm/" in url:
        parts = url.split("/scm/")
        if len(parts) == 2:
            scm_parts = parts[1].split("/")
            if len(scm_parts) >= 2:
                return f"{scm_parts[0]}/{scm_parts[1]}"

    # GitHub and Bitbucket Cloud formats
    # Remove protocol
    for prefix in ["https://", "http://", "git@"]:
        if url.startswith(prefix):
            url = url[len(prefix):]
            break

    # Handle git@ format (git@github.com:owner/repo or git@bitbucket.org:owner/repo)
    if ":" in url and "/" not in url.split(":")[0]:
        url = url.replace(":", "/")

    # Extract owner/repo
    parts = url.split("/")
    for host in ["github.com", "bitbucket.org"]:
        if host in parts:
            idx = parts.index(host)
            if len(parts) > idx + 2:
                return f"{parts[idx + 1]}/{parts[idx + 2]}"

    # Fallback: take last two parts
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"

    return url
