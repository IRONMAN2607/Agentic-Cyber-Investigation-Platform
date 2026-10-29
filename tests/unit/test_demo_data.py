from __future__ import annotations

from acip.demo_data import DEMO_INVESTIGATIONS, demo_investigations_by_type
from acip.types import TargetType


def test_demo_catalog_covers_every_target_type_and_risk_band() -> None:
    grouped = demo_investigations_by_type()

    assert len(DEMO_INVESTIGATIONS) == 2 * len(TargetType)
    assert set(grouped) == set(TargetType)
    for high, low in grouped.values():
        assert high.risk_band == "high"
        assert low.risk_band == "low"
        assert high.target_type is low.target_type
