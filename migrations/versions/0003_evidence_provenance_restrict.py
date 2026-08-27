"""Append-only provenance foreign keys become RESTRICT

Revision ID: 0003_evidence_provenance_restrict
Revises: 0002_core_domain_models
Create Date: 2026-08-27 12:00:00.000000

CASCADE on investigation_id and SET NULL on the three provenance columns both
destroyed an immutable evidence row's provenance below the ORM, where the
append-only mapper guards cannot see it:

* CASCADE  — deleting an investigation silently deleted its evidence.
* SET NULL — deleting a tool_run erased tool_run_id, which is the G1
  deterministic-origin marker, retroactively ungrounding every FACT citing it.

database.md s1 requires that parent deletion not be an integrity policy.
Evidence destruction now goes through the audited purge in the investigations
router, which records what it removed.

llm_calls carries the identical defect and is covered here for coherence: the
session-level guard in db/session.py already treats it as append-only, so
leaving its schema free to cascade would be contradictory. The table is empty
until Phase 6 introduces the first model call, so the rebuild is free now and
would be a live migration later.

SQLite cannot ALTER a constraint, so this is a table rebuild via batch mode.
On PostgreSQL the rebuild is heavier than the ALTER it would otherwise emit;
that cost is accepted once, here, in exchange for one code path that is known
to work on the engine actually in use.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003_evidence_provenance_restrict"
down_revision: str | None = "0002_core_domain_models"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _evidence_table(*, ondelete_investigation: str, ondelete_provenance: str) -> sa.Table:
    """The evidence table, parameterised by the FK behaviour under test."""
    return sa.Table(
        "evidence",
        sa.MetaData(),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("source_tool", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("time_confidence", sa.String(length=32), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("entities", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("artifact_id", sa.Uuid(), nullable=True),
        sa.Column("tool_run_id", sa.Uuid(), nullable=True),
        sa.Column("agent_run_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["agent_run_id"], ["agent_runs.id"], ondelete=ondelete_provenance),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete=ondelete_provenance),
        sa.ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"], ondelete=ondelete_investigation
        ),
        sa.ForeignKeyConstraint(["tool_run_id"], ["tool_runs.id"], ondelete=ondelete_provenance),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("investigation_id", "content_hash", name="uq_evidence_dedupe"),
        sa.Index("ix_evidence_investigation_id", "investigation_id"),
        sa.Index("ix_evidence_content_hash", "content_hash"),
        sa.Index("ix_evidence_inv_kind", "investigation_id", "kind"),
        sa.Index("ix_evidence_inv_observed", "investigation_id", "observed_at"),
    )


def _llm_calls_table(*, ondelete_investigation: str, ondelete_provenance: str) -> sa.Table:
    """The llm_calls table, parameterised by the FK behaviour under test."""
    return sa.Table(
        "llm_calls",
        sa.MetaData(),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("agent_run_id", sa.Uuid(), nullable=True),
        sa.Column("task_id", sa.String(length=64), nullable=True),
        sa.Column("task_class", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("prompt_name", sa.String(length=128), nullable=False),
        sa.Column("prompt_version", sa.String(length=32), nullable=False),
        sa.Column("tokens_in", sa.Integer(), nullable=False),
        sa.Column("tokens_out", sa.Integer(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("cost_estimate_usd", sa.Float(), nullable=False),
        sa.Column("finish_reason", sa.String(length=32), nullable=False),
        sa.Column("retries", sa.Integer(), nullable=False),
        sa.Column("schema_valid", sa.Boolean(), nullable=False),
        sa.Column("fallback_from", sa.String(length=128), nullable=True),
        sa.Column("temperature", sa.Float(), nullable=False),
        sa.Column("seed", sa.Integer(), nullable=True),
        sa.Column("nondeterminism_risk", sa.String(length=32), nullable=False),
        sa.Column("grounding_violations", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_run_id"], ["agent_runs.id"], ondelete=ondelete_provenance),
        sa.ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"], ondelete=ondelete_investigation
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.Index("ix_llm_calls_investigation_id", "investigation_id"),
        sa.Index("ix_llm_calls_created_at", "created_at"),
    )


def _rebuild(target: sa.Table) -> None:
    with op.batch_alter_table(target.name, copy_from=target, recreate="always"):
        pass


def _apply(*, ondelete_investigation: str, ondelete_provenance: str) -> None:
    for build in (_evidence_table, _llm_calls_table):
        _rebuild(
            build(
                ondelete_investigation=ondelete_investigation,
                ondelete_provenance=ondelete_provenance,
            )
        )


def upgrade() -> None:
    _apply(ondelete_investigation="RESTRICT", ondelete_provenance="RESTRICT")


def downgrade() -> None:
    _apply(ondelete_investigation="CASCADE", ondelete_provenance="SET NULL")
