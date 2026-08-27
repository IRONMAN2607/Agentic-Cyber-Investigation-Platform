from __future__ import annotations

import socket
from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

from acip.core.security.net import validate_url_safe
from acip.errors import ValidationError


def _mock_getaddrinfo(ip: str) -> Callable[..., list[tuple[Any, ...]]]:
    def _mock(
        host: str, port: int | str | None, proto: int = socket.IPPROTO_TCP
    ) -> list[tuple[Any, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80))]

    return _mock


def test_valid_public_url() -> None:
    with patch("socket.getaddrinfo", side_effect=_mock_getaddrinfo("93.184.216.34")):
        res = validate_url_safe("https://example.com/test")
        assert res == "https://example.com/test"


def test_invalid_scheme_rejected() -> None:
    with pytest.raises(ValidationError, match="scheme"):
        validate_url_safe("ftp://example.com/file")

    with pytest.raises(ValidationError, match="scheme"):
        validate_url_safe("file:///etc/passwd")


def test_localhost_hostname_rejected() -> None:
    with pytest.raises(ValidationError, match="localhost"):
        validate_url_safe("http://localhost:8000/api")


def test_userinfo_rejected() -> None:
    with pytest.raises(ValidationError, match="userinfo"):
        validate_url_safe("http://admin:secret@example.com")


@pytest.mark.parametrize(
    "blocked_ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.5",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",  # noqa: S104
        "224.0.0.1",
    ],
)
def test_private_and_metadata_ips_blocked(blocked_ip: str) -> None:
    with patch("socket.getaddrinfo", side_effect=_mock_getaddrinfo(blocked_ip)):
        with pytest.raises(ValidationError, match="blocked private/reserved IP"):
            validate_url_safe(f"http://internal.service.local/{blocked_ip}")


def test_dns_resolution_failure_handled() -> None:
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        with pytest.raises(ValidationError, match="could not resolve hostname"):
            validate_url_safe("http://nonexistent-domain-123456789.invalid")
