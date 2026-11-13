"""Database connection and session management."""

import logging
import os
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.exc import OperationalError

from ..config.settings import get_data_dir
from .models import Base

logger = logging.getLogger(__name__)

# Lock for thread-safe database operations
_db_lock = threading.Lock()

# Global engine and session factory
_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _secure_directory(path: Path) -> None:
    """Set secure permissions on a directory (owner-only access)."""
    try:
        os.chmod(path, stat.S_IRWXU)  # 0o700 - rwx for owner only
    except OSError as e:
        logger.warning(f"Could not set secure permissions on {path}: {e}")


def _secure_file(path: Path) -> None:
    """Set secure permissions on a file (owner-only access)."""
    try:
        if path.exists():
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600 - rw for owner only
    except OSError as e:
        logger.warning(f"Could not set secure permissions on {path}: {e}")


def get_default_db_path() -> Path:
    """Get the default database path."""
    db_dir = get_data_dir()
    db_dir.mkdir(parents=True, exist_ok=True)
    _secure_directory(db_dir)
    return db_dir / "scanner.db"


def init_database(db_path: Path | str | None = None) -> Engine:
    """Initialize the database engine and create tables.

    Args:
        db_path: Path to SQLite database file. If None, uses default location.

    Returns:
        The SQLAlchemy engine.
    """
    global _engine, _session_factory

    if db_path is None:
        db_path = get_default_db_path()

    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _secure_directory(db_path.parent)

    connection_string = f"sqlite:///{db_path}"
    logger.debug(f"Initializing database at: {db_path}")

    _engine = create_engine(
        connection_string,
        echo=False,
        connect_args={
            "check_same_thread": False,
            "timeout": 60,  # Wait up to 60 seconds for locks
        },
        pool_pre_ping=True,  # Check connection health before using
    )

    # Enable foreign keys and WAL mode for SQLite (better concurrency)
    @event.listens_for(_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging for better concurrency
        cursor.execute("PRAGMA busy_timeout=60000")  # 60 second timeout for busy database
        cursor.execute("PRAGMA synchronous=NORMAL")  # Balance between safety and speed
        cursor.close()

    # Create all tables
    Base.metadata.create_all(_engine)

    # Migrate existing DBs: add columns introduced after initial schema
    with _engine.connect() as conn:
        try:
            conn.execute(
                text("ALTER TABLE repositories ADD COLUMN repo_type TEXT NOT NULL DEFAULT 'unknown'")
            )
            conn.commit()
        except OperationalError as e:
            # Expected when initializing an already-migrated DB
            if "duplicate column" not in str(e).lower():
                raise

    # Set secure permissions on database file
    _secure_file(db_path)

    # Create session factory
    _session_factory = sessionmaker(bind=_engine, expire_on_commit=False, autoflush=False)

    logger.info(f"Database initialized at: {db_path}")
    return _engine


def get_engine() -> Engine:
    """Get the database engine, initializing if necessary."""
    global _engine
    if _engine is None:
        init_database()
    return _engine


def get_session() -> Session:
    """Get a new database session."""
    global _session_factory
    if _session_factory is None:
        init_database()
    return _session_factory()


def _collect_session_objects(session: Session) -> list:
    """Snapshot all pending new and dirty objects from a session.

    Must be called BEFORE flush/commit so objects are still tracked.
    After a rollback, these objects get detached and need to be re-added.
    """
    return list(session.new) + list(session.dirty)


def _restore_session_objects(session: Session, objects: list) -> None:
    """Re-add detached objects to a session after a rollback."""
    for obj in objects:
        try:
            session.add(obj)
        except Exception:
            pass  # Object may already be in session


def _commit_with_retry(session: Session, max_retries: int = 10, retry_delay: float = 0.3) -> None:
    """Flush and commit session with retry logic for database locks."""
    import random
    for attempt in range(max_retries):
        # Snapshot BEFORE flush/commit — after flush starts, objects move
        # from session.new to identity_map and won't be in session.new anymore
        pending = _collect_session_objects(session)
        try:
            with _db_lock:
                session.flush()
                session.commit()
            return
        except OperationalError as e:
            if "database is locked" in str(e).lower() or "locked" in str(e).lower():
                if attempt < max_retries - 1:
                    delay = retry_delay * (2 ** attempt) + random.uniform(0, 0.5)
                    logger.debug(f"Database locked, retrying commit in {delay:.2f}s (attempt {attempt + 1}/{max_retries})")
                    session.rollback()
                    _restore_session_objects(session, pending)
                    time.sleep(delay)
                    continue
            raise


def _flush_with_retry(session: Session, max_retries: int = 10, retry_delay: float = 0.3) -> None:
    """Flush session with retry logic for database locks."""
    import random
    for attempt in range(max_retries):
        # Snapshot BEFORE flush — objects move out of session.new during flush
        pending = _collect_session_objects(session)
        try:
            with _db_lock:
                session.flush()
            return
        except OperationalError as e:
            if "database is locked" in str(e).lower() or "locked" in str(e).lower():
                if attempt < max_retries - 1:
                    delay = retry_delay * (2 ** attempt) + random.uniform(0, 0.5)
                    logger.debug(f"Database locked, retrying flush in {delay:.2f}s (attempt {attempt + 1}/{max_retries})")
                    session.rollback()
                    _restore_session_objects(session, pending)
                    time.sleep(delay)
                    continue
            raise


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Provide a transactional scope around a series of operations.

    Uses locking and retry logic to handle SQLite concurrency issues.
    Autoflush is disabled; use session.flush() or _flush_with_retry() for
    intermediate flushes when you need IDs before commit.

    Usage:
        with session_scope() as session:
            session.add(obj)
    """
    session = get_session()
    try:
        yield session
        _commit_with_retry(session)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def close_database() -> None:
    """Close the database connection."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
        _engine = None
        _session_factory = None
        logger.debug("Database connection closed")
