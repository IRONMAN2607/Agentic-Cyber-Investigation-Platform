"""Core domain models: task_runs, hypotheses, hypothesis_gaps, finding_evidence, llm_calls

Revision ID: 0002_core_domain_models
Revises: 0001_initial_schema
Create Date: 2026-08-26 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0002_core_domain_models"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. task_runs table
    op.create_table(
        "task_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.String(length=64), nullable=False),
        sa.Column("task_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("inputs", sa.JSON(), nullable=False),
        sa.Column("outputs", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_task_runs_investigation_id", "task_runs", ["investigation_id"], unique=False)
    op.create_index("ix_task_runs_task_id", "task_runs", ["task_id"], unique=False)
    op.create_index("ix_task_runs_task_type", "task_runs", ["task_type"], unique=False)

    # Add task_id column to tool_runs if absent
    with op.batch_alter_table("tool_runs") as batch_op:
        batch_op.add_column(sa.Column("task_id", sa.String(length=64), nullable=True))

    # 2. finding_evidence table
    op.create_table(
        "finding_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id", "evidence_id", "role", name="uq_finding_evidence"),
    )
    op.create_index("ix_finding_evidence_finding_id", "finding_evidence", ["finding_id"], unique=False)
    op.create_index("ix_finding_evidence_evidence_id", "finding_evidence", ["evidence_id"], unique=False)

    # 3. hypotheses table
    op.create_table(
        "hypotheses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("refutation_condition", sa.Text(), nullable=False),
        sa.Column("agent_run_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_run_id"], ["agent_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_hypotheses_investigation_id", "hypotheses", ["investigation_id"], unique=False)
    op.create_index("ix_hypotheses_status", "hypotheses", ["status"], unique=False)

    # 4. hypothesis_evidence table
    op.create_table(
        "hypothesis_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("hypothesis_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["hypothesis_id"], ["hypotheses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("hypothesis_id", "evidence_id", "role", name="uq_hypothesis_evidence"),
    )
    op.create_index("ix_hypothesis_evidence_hypothesis_id", "hypothesis_evidence", ["hypothesis_id"], unique=False)
    op.create_index("ix_hypothesis_evidence_evidence_id", "hypothesis_evidence", ["evidence_id"], unique=False)

    # 5. hypothesis_gaps table
    op.create_table(
        "hypothesis_gaps",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("hypothesis_id", sa.Uuid(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("required_tool", sa.String(length=64), nullable=True),
        sa.Column("resolved", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["hypothesis_id"], ["hypotheses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_hypothesis_gaps_hypothesis_id", "hypothesis_gaps", ["hypothesis_id"], unique=False)

    # 6. llm_calls table (model execution audit)
    op.create_table(
        "llm_calls",
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
        sa.ForeignKeyConstraint(["agent_run_id"], ["agent_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_llm_calls_investigation_id", "llm_calls", ["investigation_id"], unique=False)
    op.create_index("ix_llm_calls_created_at", "llm_calls", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_table("llm_calls")
    op.drop_table("hypothesis_gaps")
    op.drop_table("hypothesis_evidence")
    op.drop_table("hypotheses")
    op.drop_table("finding_evidence")
    with op.batch_alter_table("tool_runs") as batch_op:
        batch_op.drop_column("task_id")
    op.drop_table("task_runs")
