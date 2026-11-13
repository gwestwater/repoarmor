"""Classify GitHub org members / repo collaborators as internal vs. external.

"Internal" means the user's email matches one of the configured company domains.
GitHub doesn't expose a reliable "is this an employee" flag, so this checks four
independent sources of an email address, in priority order (most authoritative first):

1. GitHub's verified-org-domain email (GraphQL organizationVerifiedDomainEmails) - only
   present if the org has verified its domain(s) with GitHub and the user has added and
   verified a matching email on their account. Most authoritative when available. A user
   can have more than one of these (e.g. multiple verified domains on the org).
2. The org's SCIM-provisioned identity email - only present for GitHub Enterprise Cloud
   orgs with SAML SSO + SCIM provisioning, and requires an org-owner token.
3. The user's public GitHub profile email (only present if they opted in).
4. The raw git commit author email(s) from their commits (via the Search API), which
   often reveals a corporate email even when the profile email is private. Different
   commits can carry different author emails (e.g. personal on some, corporate on
   others), so all distinct emails found are considered. Tried first scoped to the
   org/repo, then broadened to a global search if that finds nothing.

Every email discovered across all four sources is checked against the internal domain
list - not just the first one found - since a user's most "authoritative" email isn't
always their corporate one (e.g. a personal profile email but a corporate commit email).
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .github_api import GitHubClient

logger = logging.getLogger(__name__)


@dataclass
class MemberIdentity:
    """Result of classifying a single GitHub username as internal or external."""
    username: str
    email: str | None
    source: str  # 'domain', 'scim', 'profile', 'commits', or 'none'
    status: str  # 'internal', 'external', or 'unknown' (no email could be found)


def _email_domain(email: str) -> str | None:
    if "@" not in email:
        return None
    return email.rsplit("@", 1)[1].lower()


def _collect_candidate_emails(
    github: GitHubClient,
    username: str,
    domain_org: str | None,
    org: str | None,
    repo: str | None,
) -> list[tuple[str, str]]:
    """Gather every discoverable (email, source) pair for a user, in priority order."""
    candidates: list[tuple[str, str]] = []

    if domain_org:
        for email in github.get_verified_domain_emails(username, domain_org):
            candidates.append((email, "domain"))

        scim_email = github.get_scim_user_email(domain_org, username)
        if scim_email:
            candidates.append((scim_email, "scim"))

    profile_email = github.get_user_profile_email(username)
    if profile_email:
        candidates.append((profile_email, "profile"))

    commit_emails = github.search_commit_author_emails(username, org=org, repo=repo)
    if not commit_emails and (org or repo):
        # Scoped search found nothing - broaden to a global search across all accessible repos.
        commit_emails = github.search_commit_author_emails(username)
    for email in commit_emails:
        candidates.append((email, "commits"))

    return candidates


def classify_member(
    github: GitHubClient,
    username: str,
    internal_domains: list[str],
    org: str | None = None,
    repo: str | None = None,
) -> MemberIdentity:
    """Determine whether a single GitHub user is internal or external based on email domain.

    Checks every discoverable email (not just the first one found) against the internal
    domain list, so a secondary or tertiary email on a company domain is still caught even
    if a more "authoritative" source returned a personal address first.
    """
    normalized_domains = {d.lower().lstrip("@") for d in internal_domains}
    domain_org = org or (repo.split("/", 1)[0] if repo else None)

    candidates = _collect_candidate_emails(github, username, domain_org, org, repo)
    if not candidates:
        return MemberIdentity(username=username, email=None, source="none", status="unknown")

    for email, source in candidates:
        if _email_domain(email) in normalized_domains:
            return MemberIdentity(username=username, email=email, source=source, status="internal")

    # No candidate matched an internal domain - report the most authoritative one found.
    email, source = candidates[0]
    return MemberIdentity(username=username, email=email, source=source, status="external")


def classify_members(
    github: GitHubClient,
    usernames: list[str],
    internal_domains: list[str],
    org: str | None = None,
    repo: str | None = None,
    max_workers: int = 8,
) -> list[MemberIdentity]:
    """Classify multiple GitHub usernames in parallel."""
    results: list[MemberIdentity] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(classify_member, github, username, internal_domains, org, repo): username
            for username in usernames
        }
        for future in as_completed(futures):
            results.append(future.result())
    return results
