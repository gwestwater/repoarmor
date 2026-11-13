"""SQLAlchemy database models for RepoArmor."""

from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Text, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class Repository(Base):
    """Model for scanned repositories."""

    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(Text, unique=True, index=True)
    name: Mapped[str] = mapped_column(Text)  # owner/repo format
    visibility: Mapped[str] = mapped_column(Text, default="public")  # public, private, internal
    repo_type: Mapped[str] = mapped_column(Text, default="unknown")  # personal, org, docker, unknown
    last_scanned: Mapped[Optional[datetime]] = mapped_column(default=None)
    total_findings: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)

    # Relationships
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="repository", cascade="all, delete-orphan"
    )
    scan_history: Mapped[list["ScanHistory"]] = relationship(
        back_populates="repository", cascade="all, delete-orphan"
    )

    @property
    def org(self) -> str:
        """Extract organization/owner from repository name (owner/repo format)."""
        if "/" in self.name:
            return self.name.split("/")[0]
        return self.name

    @property
    def repo_name(self) -> str:
        """Extract just the repo name from repository name (owner/repo format)."""
        if "/" in self.name:
            return self.name.split("/", 1)[1]
        return self.name

    def __repr__(self) -> str:
        return f"<Repository(id={self.id}, name='{self.name}')>"


class Finding(Base):
    """Model for secret findings."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"))

    # Finding details from TruffleHog
    detector_type: Mapped[str] = mapped_column(Text, index=True)
    decoder_type: Mapped[Optional[str]] = mapped_column(Text, default=None)
    file_path: Mapped[str] = mapped_column(Text)
    line_number: Mapped[Optional[int]] = mapped_column(default=None)
    commit: Mapped[Optional[str]] = mapped_column(Text, default=None)
    author: Mapped[Optional[str]] = mapped_column(Text, default=None)
    author_email: Mapped[Optional[str]] = mapped_column(Text, default=None)
    commit_date: Mapped[Optional[datetime]] = mapped_column(default=None)
    message: Mapped[Optional[str]] = mapped_column(Text, default=None)

    # Secret info (hashed for dedup, not storing actual secrets)
    secret_hash: Mapped[str] = mapped_column(Text, index=True)
    redacted_secret: Mapped[Optional[str]] = mapped_column(Text, default=None)

    # Raw finding for reference
    raw_finding: Mapped[Optional[str]] = mapped_column(Text, default=None)

    # Classification
    verified_by_trufflehog: Mapped[bool] = mapped_column(default=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    repository: Mapped["Repository"] = relationship(back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, type='{self.detector_type}')>"


class ScanHistory(Base):
    """Model for tracking scan history."""

    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"))

    started_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(default=None)

    findings_count: Mapped[int] = mapped_column(default=0)
    new_findings_count: Mapped[int] = mapped_column(default=0)

    # Scan configuration used
    scan_config: Mapped[Optional[str]] = mapped_column(Text, default=None)

    # Status: running, completed, failed, cancelled
    status: Mapped[str] = mapped_column(Text, default="running")
    error_message: Mapped[Optional[str]] = mapped_column(Text, default=None)

    # Relationships
    repository: Mapped["Repository"] = relationship(back_populates="scan_history")

    def __repr__(self) -> str:
        return f"<ScanHistory(id={self.id}, repo_id={self.repo_id}, status='{self.status}')>"




