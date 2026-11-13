"""Tests for input validators."""

import pytest

from repoarmor.cli.validators import (
    validate_repo_url,
    validate_github_url,
    validate_finding_ids,
)


class TestValidateRepoUrl:
    """Tests for repository URL validation."""

    # GitHub URLs

    def test_github_https_url(self):
        """Test standard GitHub HTTPS URL."""
        url = validate_repo_url("https://github.com/owner/repo")
        assert url == "https://github.com/owner/repo"

    def test_github_https_url_with_git_suffix(self):
        """Test GitHub HTTPS URL with .git suffix."""
        url = validate_repo_url("https://github.com/owner/repo.git")
        assert url == "https://github.com/owner/repo"

    def test_github_ssh_url(self):
        """Test GitHub SSH URL format."""
        url = validate_repo_url("git@github.com:owner/repo.git")
        assert url == "https://github.com/owner/repo"

    def test_github_url_with_trailing_slash(self):
        """Test GitHub URL with trailing slash."""
        url = validate_repo_url("https://github.com/owner/repo/")
        assert url == "https://github.com/owner/repo"

    # Azure DevOps URLs

    def test_azure_devops_https_url(self):
        """Test Azure DevOps HTTPS URL."""
        url = validate_repo_url("https://dev.azure.com/myorg/myproject/_git/myrepo")
        assert url == "https://dev.azure.com/myorg/myproject/_git/myrepo"

    def test_azure_devops_https_with_git_suffix(self):
        """Test Azure DevOps HTTPS URL with .git suffix."""
        url = validate_repo_url("https://dev.azure.com/myorg/myproject/_git/myrepo.git")
        assert url == "https://dev.azure.com/myorg/myproject/_git/myrepo"

    def test_azure_devops_https_with_trailing_slash(self):
        """Test Azure DevOps URL with trailing slash."""
        url = validate_repo_url("https://dev.azure.com/myorg/myproject/_git/myrepo/")
        assert url == "https://dev.azure.com/myorg/myproject/_git/myrepo"

    def test_azure_devops_with_user_prefix(self):
        """Test Azure DevOps URL with user@ prefix."""
        url = validate_repo_url("https://myorg@dev.azure.com/myorg/myproject/_git/myrepo")
        assert url == "https://myorg@dev.azure.com/myorg/myproject/_git/myrepo"

    def test_azure_devops_legacy_visualstudio(self):
        """Test legacy Visual Studio URL format."""
        url = validate_repo_url("https://myorg.visualstudio.com/myproject/_git/myrepo")
        assert url == "https://myorg.visualstudio.com/myproject/_git/myrepo"

    def test_azure_devops_ssh_url(self):
        """Test Azure DevOps SSH URL."""
        url = validate_repo_url("git@ssh.dev.azure.com:v3/myorg/myproject/myrepo")
        assert url == "git@ssh.dev.azure.com:v3/myorg/myproject/myrepo"

    # Bitbucket URLs

    def test_bitbucket_https_url(self):
        """Test Bitbucket HTTPS URL."""
        url = validate_repo_url("https://bitbucket.org/owner/repo")
        assert url == "https://bitbucket.org/owner/repo"

    def test_bitbucket_https_with_git_suffix(self):
        """Test Bitbucket HTTPS URL with .git suffix."""
        url = validate_repo_url("https://bitbucket.org/owner/repo.git")
        assert url == "https://bitbucket.org/owner/repo"

    def test_bitbucket_https_with_trailing_slash(self):
        """Test Bitbucket URL with trailing slash."""
        url = validate_repo_url("https://bitbucket.org/owner/repo/")
        assert url == "https://bitbucket.org/owner/repo"

    def test_bitbucket_ssh_url(self):
        """Test Bitbucket SSH URL."""
        url = validate_repo_url("git@bitbucket.org:owner/repo.git")
        assert url == "https://bitbucket.org/owner/repo"

    def test_bitbucket_no_protocol(self):
        """Test Bitbucket URL without protocol."""
        url = validate_repo_url("bitbucket.org/owner/repo")
        assert url == "https://bitbucket.org/owner/repo"

    # Invalid URLs

    def test_invalid_url(self):
        """Test invalid URL raises error."""
        with pytest.raises(ValueError):
            validate_repo_url("not-a-url")

    def test_unsupported_host_url(self):
        """Test unsupported host URL raises error."""
        with pytest.raises(ValueError):
            validate_repo_url("https://gitlab.com/owner/repo")

    # Backward compatibility alias

    def test_validate_github_url_alias(self):
        """Test that validate_github_url still works as alias."""
        url = validate_github_url("https://github.com/owner/repo")
        assert url == "https://github.com/owner/repo"


class TestValidateFindingIds:
    """Tests for finding ID validation."""

    def test_single_id(self):
        """Test single ID."""
        ids = validate_finding_ids("5")
        assert ids == [5]

    def test_comma_separated(self):
        """Test comma-separated IDs."""
        ids = validate_finding_ids("1, 3, 5")
        assert ids == [1, 3, 5]

    def test_range(self):
        """Test ID range."""
        ids = validate_finding_ids("1-5")
        assert ids == [1, 2, 3, 4, 5]

    def test_mixed(self):
        """Test mixed IDs and ranges."""
        ids = validate_finding_ids("1, 3-5, 7")
        assert ids == [1, 3, 4, 5, 7]

    def test_deduplication(self):
        """Test duplicate IDs are removed."""
        ids = validate_finding_ids("1, 1, 2, 2-3")
        assert ids == [1, 2, 3]

    def test_invalid_id(self):
        """Test invalid ID raises error."""
        with pytest.raises(ValueError):
            validate_finding_ids("abc")

    def test_invalid_range(self):
        """Test invalid range raises error."""
        with pytest.raises(ValueError):
            validate_finding_ids("5-3")
