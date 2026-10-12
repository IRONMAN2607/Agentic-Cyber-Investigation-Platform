"""Phase 5 evidence graph entities and entity_edges tables

Revision ID: 0004_evidence_graph_entities_and_edges
Revises: 0003_evidence_provenance_restrict
Create Date: 2026-10-12 12:00:00.000000

Adds the canonical entities and evidence-backed entity_edges tables to support
deterministic evidence graph traversal and cross-source attack correlation.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_evidence_graph_entities_and_edges"
down_revision: str | None = "0003_evidence_provenance_restrict"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "entities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("value_normalized", sa.String(length=256), nullable=False),
        sa.Column("value_raw_first_seen", sa.String(length=256), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "investigation_id", "type", "value_normalized", name="uq_investigation_entity"
        ),
    )
    op.create_index("ix_entities_investigation_id", "entities", ["investigation_id"], unique=False)
    op.create_index("ix_entities_type", "entities", ["type"], unique=False)
    op.create_index(
        "ix_entities_value_normalized", "entities", ["value_normalized"], unique=False
    )

    op.create_table(
        "entity_edges",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("src_entity_id", sa.Uuid(), nullable=False),
        sa.Column("dst_entity_id", sa.Uuid(), nullable=False),
        sa.Column("relation", sa.String(length=64), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["src_entity_id"], ["entities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["dst_entity_id"], ["entities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_entity_edges_investigation_id", "entity_edges", ["investigation_id"], unique=False
    )
    op.create_index(
        "ix_entity_edges_src_entity_id", "entity_edges", ["src_entity_id"], unique=False
    )
    op.create_index(
        "ix_entity_edges_dst_entity_id", "entity_edges", ["dst_entity_id"], unique=False
    )
    op.create_index("ix_entity_edges_relation", "entity_edges", ["relation"], unique=False)
    op.create_index(
        "ix_entity_edges_evidence_id", "entity_edges", ["evidence_id"], unique=False
    )
    op.create_index(
        "ix_entity_edges_src", "entity_edges", ["investigation_id", "src_entity_id"], unique=False
    )
    op.create_index(
        "ix_entity_edges_dst", "entity_edges", ["investigation_id", "dst_entity_id"], unique=False
    )


def downgrade() -> None:
    op.drop_table("entity_edges")
    op.drop_table("entities")
