"""Declarative base and portable column types.

The schema deliberately avoids dialect-specific features so the same models run
on SQLite (local development, M1) and PostgreSQL (deployment target). The two
places where dialects differ are handled here:

* ``JSONColumn`` uses ``JSONB`` on PostgreSQL and ``JSON`` elsewhere.
* ``UTCDateTime`` guarantees timezone-aware UTC values in both directions,
  because SQLite discards ``tzinfo``.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.types import TypeDecorator

JSONColumn = sa.JSON().with_variant(JSONB, "postgresql")


class UTCDateTime(TypeDecorator[dt.datetime]):
    """Store timezone-aware datetimes as UTC and read them back aware.

    Rejects naive datetimes on write. Timestamp correctness is load-bearing for
    an investigation timeline, so an ambiguous value is a bug, not a default.
    """

    impl = sa.DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(
        self, value: dt.datetime | None, dialect: sa.Dialect
    ) -> dt.datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime rejected; pass an aware UTC datetime")
        return value.astimezone(dt.UTC)

    def process_result_value(
        self, value: dt.datetime | None, dialect: sa.Dialect
    ) -> dt.datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=dt.UTC)
        return value.astimezone(dt.UTC)


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    type_annotation_map = {  # noqa: RUF012 - SQLAlchemy API expects a plain dict
        dict[str, Any]: JSONColumn,
        list[str]: JSONColumn,
        dt.datetime: UTCDateTime,
    }


def utcnow() -> dt.datetime:
    """Timezone-aware current time. Used as a column default."""
    return dt.datetime.now(dt.UTC)
