"""Configuration loading and validation with Pydantic."""

import logging
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


def _repoint_legacy_paths(config_file: Path, legacy_dir: Path, new_dir: Path) -> None:
    """Rewrite paths in a copied config that still point into the legacy directory."""
    try:
        text = config_file.read_text(encoding="utf-8")
        updated = text.replace(str(legacy_dir), str(new_dir)).replace("~/.secret-scanner", "~/.repoarmor")
        if updated != text:
            config_file.write_text(updated, encoding="utf-8")
    except (OSError, UnicodeError) as e:
        logger.warning(f"Could not update paths in {config_file}: {e}")


def get_data_dir() -> Path:
    """Get the data directory (~/.repoarmor).

    On first run after upgrading from secret-scanner, the legacy ~/.secret-scanner
    directory is copied to ~/.repoarmor and then renamed to ~/.secret-scanner.migrated
    as a backup, so an old secret-scanner install no longer sees the data.
    If the copy fails, the legacy directory keeps being used.
    """
    new_dir = Path.home() / ".repoarmor"
    legacy_dir = Path.home() / ".secret-scanner"
    if new_dir.exists() or not legacy_dir.is_dir():
        return new_dir

    # Copy to a temporary sibling first so an interrupted copy never leaves a partial ~/.repoarmor
    tmp_dir = new_dir.with_name(".repoarmor.migrating")
    try:
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir)
        shutil.copytree(legacy_dir, tmp_dir)  # copy2 keeps the restrictive file permissions
        _repoint_legacy_paths(tmp_dir / "config.yaml", legacy_dir, new_dir)
        tmp_dir.rename(new_dir)
    except OSError as e:
        logger.warning(f"Could not migrate {legacy_dir} to {new_dir}: {e}. Using {legacy_dir}.")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return legacy_dir

    backup_dir = legacy_dir.with_name(".secret-scanner.migrated")
    try:
        legacy_dir.rename(backup_dir)
        backup_note = f"The old directory was renamed to {backup_dir} as a backup."
    except OSError as e:
        logger.warning(f"Could not rename {legacy_dir} to {backup_dir}: {e}")
        backup_note = f"The old directory {legacy_dir} was left in place and can be deleted."

    print(f"RepoArmor: moved your data from {legacy_dir} to {new_dir}. {backup_note}", file=sys.stderr)
    return new_dir


class DatabaseConfig(BaseModel):
    """Database configuration."""
    path: Path = Field(default_factory=lambda: get_data_dir() / "scanner.db")


class ScannerConfig(BaseModel):
    """Scanner configuration."""
    trufflehog_path: str = Field(default="trufflehog")
    default_depth: int | None = Field(default=None, ge=1)  # None = scan all commits
    parallel_scans: int = Field(default=2, ge=1, le=10)  # Keep low for SQLite compatibility
    timeout: int = Field(default=600, ge=30)  # seconds - increased for full scans
    only_verified: bool = Field(default=False)


class OutputConfig(BaseModel):
    """Output configuration."""
    default_format: str = Field(default="table")
    date_format: str = Field(default="%Y-%m-%d %H:%M")

    @field_validator("default_format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        allowed = ["table", "json", "csv"]
        if v not in allowed:
            raise ValueError(f"default_format must be one of: {allowed}")
        return v


class LLMConfig(BaseModel):
    """LLM configuration for chat command."""
    provider: str = Field(default="openai")
    model: str | None = Field(default=None)
    api_key: str | None = Field(default=None)

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        allowed = ["openai"]
        if v not in allowed:
            raise ValueError(f"provider must be one of: {allowed}")
        return v


class IdentityConfig(BaseModel):
    """Configuration for classifying GitHub members/collaborators as internal vs. external."""
    internal_email_domains: list[str] = Field(default_factory=list)


class Settings(BaseModel):
    """Main settings model."""
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    ignore_patterns: list[str] = Field(default_factory=lambda: [
        "*.test.js",
        "*.test.ts",
        "*_test.go",
        "*_test.py",
        "vendor/*",
        "node_modules/*",
        ".git/*",
    ])
    output: OutputConfig = Field(default_factory=OutputConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    identity: IdentityConfig = Field(default_factory=IdentityConfig)


def get_config_path() -> Path:
    """Get the default config file path."""
    return get_data_dir() / "config.yaml"


def get_default_config() -> Settings:
    """Get the default configuration."""
    return Settings()


def load_config(config_path: Path | str | None = None) -> Settings:
    """Load configuration from file.

    Args:
        config_path: Path to config file. If None, uses default location.

    Returns:
        Loaded Settings object.
    """
    if config_path is None:
        config_path = get_config_path()

    config_path = Path(config_path)

    if not config_path.exists():
        logger.debug(f"Config file not found at {config_path}, using defaults")
        return get_default_config()

    try:
        with open(config_path, "r") as f:
            data = yaml.safe_load(f) or {}

        logger.debug(f"Loaded config from {config_path}")
        return Settings(**data)

    except yaml.YAMLError as e:
        logger.error(f"Error parsing config file: {e}")
        raise ValueError(f"Invalid YAML in config file: {e}")
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        raise


def _secure_path(path: Path, is_dir: bool = False) -> None:
    """Set secure permissions on a file or directory (owner-only access)."""
    try:
        if is_dir:
            os.chmod(path, stat.S_IRWXU)  # 0o700 - rwx for owner only
        else:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600 - rw for owner only
    except OSError as e:
        logger.warning(f"Could not set secure permissions on {path}: {e}")


def save_config(settings: Settings, config_path: Path | str | None = None) -> None:
    """Save configuration to file.

    Args:
        settings: Settings object to save.
        config_path: Path to save to. If None, uses default location.
    """
    if config_path is None:
        config_path = get_config_path()

    config_path = Path(config_path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    _secure_path(config_path.parent, is_dir=True)

    # Convert to dict and handle Path objects
    data = settings.model_dump()
    data["database"]["path"] = str(settings.database.path)

    with open(config_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    # Set secure permissions on config file (may contain API keys)
    _secure_path(config_path)

    logger.info(f"Saved config to {config_path}")


# Global settings instance
_settings: Settings | None = None


def get_settings() -> Settings:
    """Get the global settings instance, loading if necessary."""
    global _settings
    if _settings is None:
        _settings = load_config()
    return _settings


def reload_settings(config_path: Path | str | None = None) -> Settings:
    """Reload settings from file."""
    global _settings
    _settings = load_config(config_path)
    return _settings
