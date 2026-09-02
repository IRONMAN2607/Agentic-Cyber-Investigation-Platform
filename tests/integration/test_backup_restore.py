from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import sqlalchemy as sa
from pydantic import SecretStr

from acip.config import Settings
from acip.core.backup import (
    BackupIntegrityError,
    create_backup,
    restore_backup,
    verify_backup,
)
from acip.db.migrate import upgrade_to_head
from acip.db.models import Artifact, Investigation, User
from acip.db.session import Database

pytestmark = pytest.mark.asyncio


async def _init_db_with_artifact(
    db_url: str, artifact_dir: Path
) -> tuple[Investigation, Artifact, bytes]:
    await upgrade_to_head(db_url)
    db = Database(db_url)

    sample_content = b"Aug 28 01:00:00 server sshd[123]: Failed password for root\n"
    content_hash = hashlib.sha256(sample_content).hexdigest()

    art_file = artifact_dir / content_hash[:2] / content_hash
    art_file.parent.mkdir(parents=True, exist_ok=True)
    art_file.write_bytes(sample_content)

    async with db.session() as session:
        user = User(
            username="admin_user",
            password_hash="hash",
            role="admin",
        )
        session.add(user)
        await session.flush()

        inv = Investigation(
            title="Backup Test Inv",
            target_type="log",
            target_value="auth.log",
            created_by=user.id,
            retention_state="reproducible",
        )
        session.add(inv)
        await session.flush()

        art = Artifact(
            investigation_id=inv.id,
            kind="linux_auth_log",
            original_filename="auth.log",
            sha256=content_hash,
            size_bytes=len(sample_content),
            storage_path=str(art_file),
            retention_state="reproducible",
        )
        session.add(art)
        await session.flush()

    await db.dispose()
    return inv, art, sample_content


async def test_create_and_restore_backup_integrity(tmp_path: Path) -> None:
    src_db = tmp_path / "source.db"
    src_artifacts = tmp_path / "source_artifacts"
    src_url = f"sqlite+aiosqlite:///{src_db.as_posix()}"

    inv, art, raw_bytes = await _init_db_with_artifact(src_url, src_artifacts)

    src_settings = Settings(
        database_url=src_url,
        artifact_dir=src_artifacts,
        secret_key=SecretStr("secret"),
    )

    backup_dest = tmp_path / "backup_snapshot"
    created = create_backup(src_settings, backup_dest)
    assert created.is_dir()
    assert (backup_dest / "acip.db").is_file()
    assert (backup_dest / "artifacts").is_dir()

    # Pre-existing destination raises FileExistsError
    with pytest.raises(FileExistsError):
        create_backup(src_settings, backup_dest)

    # Verification passes on valid backup
    verify_backup(backup_dest)

    # Restore into fresh target paths
    target_db = tmp_path / "restored.db"
    target_artifacts = tmp_path / "restored_artifacts"
    target_url = f"sqlite+aiosqlite:///{target_db.as_posix()}"

    target_settings = Settings(
        database_url=target_url,
        artifact_dir=target_artifacts,
        secret_key=SecretStr("secret"),
    )

    restore_backup(backup_dest, target_settings)
    assert target_db.is_file()
    restored_art_file = target_artifacts / art.sha256[:2] / art.sha256
    assert restored_art_file.is_file()
    assert restored_art_file.read_bytes() == raw_bytes

    # Restored DB has rebased artifact path and is queryable
    restored_db = Database(target_url)
    try:
        async with restored_db.session() as session:
            loaded_inv = await session.get(Investigation, inv.id)
            assert loaded_inv is not None
            assert loaded_inv.title == "Backup Test Inv"

            loaded_art = await session.scalar(sa.select(Artifact).where(Artifact.id == art.id))
            assert loaded_art is not None
            assert loaded_art.storage_path == str(restored_art_file)
            assert loaded_art.sha256 == art.sha256
    finally:
        await restored_db.dispose()


async def test_verify_backup_detects_digest_tampering(tmp_path: Path) -> None:
    src_db = tmp_path / "src_tamper.db"
    src_artifacts = tmp_path / "src_tamper_artifacts"
    src_url = f"sqlite+aiosqlite:///{src_db.as_posix()}"

    _, art, _ = await _init_db_with_artifact(src_url, src_artifacts)
    src_settings = Settings(
        database_url=src_url,
        artifact_dir=src_artifacts,
        secret_key=SecretStr("s"),
    )

    backup_dest = tmp_path / "backup_tamper"
    create_backup(src_settings, backup_dest)

    # Tamper with the artifact file in backup
    art_file_in_backup = backup_dest / "artifacts" / art.sha256[:2] / art.sha256
    art_file_in_backup.write_bytes(b"corrupted contents")

    with pytest.raises(BackupIntegrityError, match="digest mismatch"):
        verify_backup(backup_dest)


async def test_verify_backup_detects_missing_artifact(tmp_path: Path) -> None:
    src_db = tmp_path / "src_missing.db"
    src_artifacts = tmp_path / "src_missing_artifacts"
    src_url = f"sqlite+aiosqlite:///{src_db.as_posix()}"

    _, art, _ = await _init_db_with_artifact(src_url, src_artifacts)
    src_settings = Settings(
        database_url=src_url,
        artifact_dir=src_artifacts,
        secret_key=SecretStr("s"),
    )

    backup_dest = tmp_path / "backup_missing"
    create_backup(src_settings, backup_dest)

    # Remove the artifact file
    art_file_in_backup = backup_dest / "artifacts" / art.sha256[:2] / art.sha256
    art_file_in_backup.unlink()

    with pytest.raises(BackupIntegrityError, match="missing source bytes"):
        verify_backup(backup_dest)


async def test_restore_refuses_populated_destination(tmp_path: Path) -> None:
    src_db = tmp_path / "src_refuse.db"
    src_artifacts = tmp_path / "src_refuse_artifacts"
    src_url = f"sqlite+aiosqlite:///{src_db.as_posix()}"

    await _init_db_with_artifact(src_url, src_artifacts)
    src_settings = Settings(
        database_url=src_url,
        artifact_dir=src_artifacts,
        secret_key=SecretStr("s"),
    )

    backup_dest = tmp_path / "backup_refuse"
    create_backup(src_settings, backup_dest)

    # Attempting to restore onto an existing DB
    with pytest.raises(FileExistsError, match="restore database already exists"):
        restore_backup(backup_dest, src_settings)
