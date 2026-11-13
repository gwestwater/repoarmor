import os
import stat
from pathlib import Path

from repoarmor.config import settings


def _use_home(monkeypatch, home: Path) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))


def test_data_dir_defaults_to_repoarmor(tmp_path, monkeypatch):
    _use_home(monkeypatch, tmp_path)

    assert settings.get_data_dir() == tmp_path / ".repoarmor"
    assert not (tmp_path / ".secret-scanner").exists()


def test_legacy_dir_is_moved_on_first_run_and_kept_as_backup(tmp_path, monkeypatch, capsys):
    _use_home(monkeypatch, tmp_path)
    legacy = tmp_path / ".secret-scanner"
    legacy.mkdir()
    db = legacy / "scanner.db"
    db.write_bytes(b"findings")
    os.chmod(db, stat.S_IRUSR | stat.S_IWUSR)
    (legacy / "config.yaml").write_text("database: {}\n")

    new_dir = settings.get_data_dir()

    assert new_dir == tmp_path / ".repoarmor"
    assert (new_dir / "scanner.db").read_bytes() == b"findings"
    assert (new_dir / "config.yaml").read_text() == "database: {}\n"
    assert stat.S_IMODE((new_dir / "scanner.db").stat().st_mode) == 0o600
    assert not legacy.exists()
    assert (tmp_path / ".secret-scanner.migrated" / "scanner.db").read_bytes() == b"findings"
    assert not (tmp_path / ".repoarmor.migrating").exists()
    assert "moved your data" in capsys.readouterr().err


def test_migrated_config_paths_are_repointed_to_new_dir(tmp_path, monkeypatch):
    _use_home(monkeypatch, tmp_path)
    legacy = tmp_path / ".secret-scanner"
    legacy.mkdir()
    (legacy / "config.yaml").write_text(
        f"database:\n  path: {legacy}/scanner.db\nother:\n  path: ~/.secret-scanner/x.db\n"
    )

    new_dir = settings.get_data_dir()

    text = (new_dir / "config.yaml").read_text()
    assert f"path: {new_dir}/scanner.db" in text
    assert "path: ~/.repoarmor/x.db" in text
    assert ".secret-scanner" not in text


def test_migration_runs_only_once(tmp_path, monkeypatch, capsys):
    _use_home(monkeypatch, tmp_path)
    legacy = tmp_path / ".secret-scanner"
    legacy.mkdir()
    (legacy / "scanner.db").write_bytes(b"old")

    settings.get_data_dir()
    capsys.readouterr()
    legacy.mkdir()
    (legacy / "scanner.db").write_bytes(b"recreated by an old install")

    new_dir = settings.get_data_dir()

    assert (new_dir / "scanner.db").read_bytes() == b"old"
    assert capsys.readouterr().err == ""


def test_rename_failure_keeps_migrated_data_and_old_dir(tmp_path, monkeypatch, capsys):
    _use_home(monkeypatch, tmp_path)
    legacy = tmp_path / ".secret-scanner"
    legacy.mkdir()
    (legacy / "scanner.db").write_bytes(b"old")
    (tmp_path / ".secret-scanner.migrated").mkdir()
    (tmp_path / ".secret-scanner.migrated" / "x").write_text("occupied")

    new_dir = settings.get_data_dir()

    assert (new_dir / "scanner.db").read_bytes() == b"old"
    assert legacy.exists()
    assert "left in place" in capsys.readouterr().err


def test_existing_new_dir_is_never_overwritten(tmp_path, monkeypatch):
    _use_home(monkeypatch, tmp_path)
    (tmp_path / ".secret-scanner").mkdir()
    (tmp_path / ".secret-scanner" / "scanner.db").write_bytes(b"old")
    new = tmp_path / ".repoarmor"
    new.mkdir()
    (new / "scanner.db").write_bytes(b"new")

    assert settings.get_data_dir() == new
    assert (new / "scanner.db").read_bytes() == b"new"


def test_failed_copy_falls_back_to_legacy_dir(tmp_path, monkeypatch):
    _use_home(monkeypatch, tmp_path)
    legacy = tmp_path / ".secret-scanner"
    legacy.mkdir()
    (legacy / "scanner.db").write_bytes(b"old")

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(settings.shutil, "copytree", boom)

    assert settings.get_data_dir() == legacy
    assert not (tmp_path / ".repoarmor").exists()
    assert not (tmp_path / ".repoarmor.migrating").exists()


def test_config_and_db_paths_follow_migrated_dir(tmp_path, monkeypatch):
    _use_home(monkeypatch, tmp_path)
    (tmp_path / ".secret-scanner").mkdir()

    assert settings.get_config_path() == tmp_path / ".repoarmor" / "config.yaml"
    assert settings.DatabaseConfig().path == tmp_path / ".repoarmor" / "scanner.db"
