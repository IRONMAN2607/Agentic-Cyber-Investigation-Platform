from __future__ import annotations

import datetime as dt
import uuid

from acip.core.detection.auth_rules import (
    RULE_BRUTEFORCE,
    RULE_PRIVILEGE_ESCALATION,
    RULE_SUCCESS_AFTER_BRUTEFORCE,
    RULE_USER_ENUMERATION,
    AuthEventView,
    evaluate_auth_rules,
)


def _make_event_view(
    event_type: str,
    *,
    user: str | None = None,
    source_ip: str | None = "203.0.113.55",
    observed_at: dt.datetime | None = None,
    target_user: str | None = None,
    command: str | None = None,
    invalid_user: bool = False,
) -> AuthEventView:
    return AuthEventView(
        evidence_id=uuid.uuid4(),
        event_type=event_type,
        observed_at=observed_at or dt.datetime.now(dt.UTC),
        user=user,
        source_ip=source_ip,
        target_user=target_user,
        command=command,
        invalid_user=invalid_user,
    )


def test_brute_force_positive_and_negative() -> None:
    now = dt.datetime.now(dt.UTC)
    # 5 failures in 30 seconds -> Positive brute force
    burst = [
        _make_event_view(
            "auth_failure", user="admin", observed_at=now + dt.timedelta(seconds=i * 5)
        )
        for i in range(5)
    ]
    # Followed by a success
    burst.append(
        _make_event_view("auth_success", user="admin", observed_at=now + dt.timedelta(seconds=35))
    )

    hits = evaluate_auth_rules(burst)
    rule_ids = {h.rule_id for h in hits}
    assert RULE_BRUTEFORCE in rule_ids
    assert RULE_SUCCESS_AFTER_BRUTEFORCE in rule_ids

    # Near-miss negative: only 2 failures -> should not trigger brute force
    sub_burst = [
        _make_event_view(
            "auth_failure", user="admin", observed_at=now + dt.timedelta(seconds=i * 5)
        )
        for i in range(2)
    ]
    neg_hits = evaluate_auth_rules(sub_burst)
    neg_rule_ids = {h.rule_id for h in neg_hits}
    assert RULE_BRUTEFORCE not in neg_rule_ids


def test_user_enumeration_positive() -> None:
    now = dt.datetime.now(dt.UTC)
    # 4 distinct invalid users from same IP
    enum_events = [
        _make_event_view(
            "invalid_user",
            user=f"user_{i}",
            invalid_user=True,
            observed_at=now + dt.timedelta(seconds=i),
        )
        for i in range(4)
    ]
    hits = evaluate_auth_rules(enum_events)
    rule_ids = {h.rule_id for h in hits}
    assert RULE_USER_ENUMERATION in rule_ids


def test_privilege_escalation_positive() -> None:
    now = dt.datetime.now(dt.UTC)
    # Failed logins followed by success and root sudo
    events = [
        _make_event_view(
            "auth_failure", user="deploy", observed_at=now + dt.timedelta(seconds=i * 5)
        )
        for i in range(5)
    ]
    events.append(
        _make_event_view("auth_success", user="deploy", observed_at=now + dt.timedelta(seconds=30))
    )
    events.append(
        _make_event_view(
            "sudo_command",
            user="deploy",
            target_user="root",
            command="/bin/bash",
            observed_at=now + dt.timedelta(seconds=45),
        )
    )
    hits = evaluate_auth_rules(events)
    rule_ids = {h.rule_id for h in hits}
    assert RULE_PRIVILEGE_ESCALATION in rule_ids


def test_clean_events_produce_zero_hits() -> None:
    now = dt.datetime.now(dt.UTC)
    clean_events = [
        _make_event_view("auth_success", user="alice", observed_at=now),
        _make_event_view("auth_success", user="bob", observed_at=now + dt.timedelta(minutes=5)),
    ]
    hits = evaluate_auth_rules(clean_events)
    assert len(hits) == 0
