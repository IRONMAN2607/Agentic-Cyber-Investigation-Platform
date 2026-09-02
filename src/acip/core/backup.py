"""Portable SQLite backup and restore with artifact-integrity verification.

The database alone is not an ACIP backup: evidence provenance can point to raw
artifact bytes.  A backup is therefore a directory containing a SQLite snapshot
and the content-addressed artifact tree.  The verifier is intentionally usable
both before a backup is accepted and after it is restored.
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path

from acip.config import Settings

_DATABASE_NAME = "acip.db"
_ARTIFACT_DIR_NAME = "artifacts"


class BackupIntegrityError(ValueError):
    """A backup is incomplete or its artifact bytes do not match the database."""


def create_backup(settings: Settings, destination: Path) -> Path:
    """Create and verify a consistent SQLite/artifact snapshot at ``destination``.

    SQLite's backup API includes WAL state, unlike copying the ``.db`` file.
    The database snapshot is taken before the artifact tree so every artifact
    it references has a chance to be copied.  Callers must not purge artifacts
    while a backup is running.
    """
    source_db = _sqlite_path(settings.database_url)
    source_artifacts = settings.artifact_dir.resolve()
    destination = destination.resolve()
    if destination.exists():
        raise FileExistsError(f"backup destination already exists: {destination}")
    if not source_db.is_file():
        raise FileNotFoundError(f"database does not exist: {source_db}")

    staging = destination.parent / f".{destination.name}.tmp-{uuid.uuid4().hex}"
    try:
        staging.mkdir(parents=True)
        _sqlite_snapshot(source_db, staging / _DATABASE_NAME)
        shutil.copytree(source_artifacts, staging / _ARTIFACT_DIR_NAME, dirs_exist_ok=True)
        verify_backup(staging)
        staging.rename(destination)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination


def restore_backup(source: Path, settings: Settings) -> None:
    """Verify and restore ``source`` into empty configured SQLite/artifact paths.

    Refusing populated destinations makes this operation recoverable: an
    operator must choose a new empty location or move existing data aside before
    a restore can replace it.  Artifact paths are rebased to the configured
    artifact root so the restored application can read them immediately.
    """
    source = source.resolve()
    verify_backup(source)
    target_db = _sqlite_path(settings.database_url)
    target_artifacts = settings.artifact_dir.resolve()
    if target_db.exists():
        raise FileExistsError(f"restore database already exists: {target_db}")
    if target_artifacts.exists() and any(target_artifacts.iterdir()):
        raise FileExistsError(f"restore artifact directory is not empty: {target_artifacts}")

    target_db.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(source / _DATABASE_NAME, target_db)
        shutil.copytree(source / _ARTIFACT_DIR_NAME, target_artifacts, dirs_exist_ok=True)
        _rebase_artifact_paths(target_db, target_artifacts)
        _verify_snapshot(target_db, target_artifacts)
    except BaseException:
        # The caller supplied empty targets, so removing an incomplete restore
        # cannot destroy prior data.
        target_db.unlink(missing_ok=True)
        shutil.rmtree(target_artifacts, ignore_errors=True)
        raise


def verify_backup(source: Path) -> None:
    """Raise when a backup lacks required source bytes or has a digest mismatch."""
    source = source.resolve()
    _verify_snapshot(source / _DATABASE_NAME, source / _ARTIFACT_DIR_NAME)


def _sqlite_path(url: str) -> Path:
    if not url.startswith("sqlite") or ":memory:" in url or ":///" not in url:
        raise ValueError("backup and restore currently require a file-backed SQLite database")
    return Path(url.split("///", 1)[1]).resolve()


def _sqlite_snapshot(source: Path, destination: Path) -> None:
    with (
        closing(sqlite3.connect(source)) as source_connection,
        closing(sqlite3.connect(destination)) as target_connection,
    ):
        source_connection.backup(target_connection)


def _verify_snapshot(database: Path, artifact_root: Path) -> None:
    if not database.is_file():
        raise BackupIntegrityError(f"backup database is missing: {database}")
    if not artifact_root.is_dir():
        raise BackupIntegrityError(f"backup artifact directory is missing: {artifact_root}")

    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute(
            "SELECT artifacts.sha256, investigations.retention_state "
            "FROM artifacts JOIN investigations ON artifacts.investigation_id = investigations.id"
        ).fetchall()

    failures: list[str] = []
    for sha256, retention_state in rows:
        expected = artifact_root / sha256[:2] / sha256
        if not expected.is_file():
            if retention_state == "reproducible":
                failures.append(f"missing source bytes for reproducible artifact {sha256}")
            continue
        if _sha256(expected) != sha256:
            failures.append(f"digest mismatch for artifact {sha256}")
    if failures:
        raise BackupIntegrityError("backup integrity failed: " + "; ".join(failures))


def _rebase_artifact_paths(database: Path, artifact_root: Path) -> None:
    with closing(sqlite3.connect(database)) as connection:
        hashes = connection.execute("SELECT id, sha256 FROM artifacts").fetchall()
        for artifact_id, sha256 in hashes:
            path = artifact_root / sha256[:2] / sha256
            connection.execute(
                "UPDATE artifacts SET storage_path = ? WHERE id = ?", (str(path), artifact_id)
            )
        connection.commit()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
