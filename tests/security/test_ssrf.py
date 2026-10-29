from __future__ import annotations

import ipaddress
from typing import Any
from unittest.mock import patch

import pytest

from acip.core.security.ssrf import (
    SafeHTTPFetcher,
    is_ip_forbidden,
    validate_url_ssrf_safe,
)
from acip.errors import SSRFProtectionError, ValidationError


def test_is_ip_forbidden_loopback() -> None:
    assert is_ip_forbidden(ipaddress.ip_address("127.0.0.1"))[0] is True
    assert is_ip_forbidden(ipaddress.ip_address("127.0.0.254"))[0] is True
    assert is_ip_forbidden(ipaddress.ip_address("::1"))[0] is True


def test_is_ip_forbidden_rfc1918_private() -> None:
    assert is_ip_forbidden(ipaddress.ip_address("10.0.0.1"))[0] is True
    assert is_ip_forbidden(ipaddress.ip_address("172.16.0.1"))[0] is True
    assert is_ip_forbidden(ipaddress.ip_address("172.31.255.255"))[0] is True
    assert is_ip_forbidden(ipaddress.ip_address("192.168.1.1"))[0] is True
    assert is_ip_forbidden(ipaddress.ip_address("fc00::1"))[0] is True
    assert is_ip_forbidden(ipaddress.ip_address("fd00::1"))[0] is True


def test_is_ip_forbidden_link_local_and_metadata() -> None:
    # AWS / Azure / GCP Metadata IP
    assert is_ip_forbidden(ipaddress.ip_address("169.254.169.254"))[0] is True
    # Alibaba Metadata IP
    assert is_ip_forbidden(ipaddress.ip_address("100.100.100.200"))[0] is True
    # AWS ECS task metadata
    assert is_ip_forbidden(ipaddress.ip_address("169.254.170.2"))[0] is True
    # AWS IPv6 Metadata
    assert is_ip_forbidden(ipaddress.ip_address("fd00:ec2::254"))[0] is True
    # IPv6 link-local
    assert is_ip_forbidden(ipaddress.ip_address("fe80::1"))[0] is True


def test_is_ip_forbidden_cgnat_and_multicast_and_unspecified() -> None:
    assert is_ip_forbidden(ipaddress.ip_address("100.64.0.1"))[0] is True
    assert is_ip_forbidden(ipaddress.ip_address("224.0.0.1"))[0] is True
    assert is_ip_forbidden(ipaddress.ip_address("ff02::1"))[0] is True
    assert is_ip_forbidden(ipaddress.ip_address("0.0.0.0"))[0] is True  # noqa: S104
    assert is_ip_forbidden(ipaddress.ip_address("::"))[0] is True
    assert is_ip_forbidden(ipaddress.ip_address("255.255.255.255"))[0] is True


def test_is_ip_forbidden_ipv4_mapped_ipv6() -> None:
    assert is_ip_forbidden(ipaddress.ip_address("::ffff:127.0.0.1"))[0] is True
    assert is_ip_forbidden(ipaddress.ip_address("::ffff:169.254.169.254"))[0] is True
    assert is_ip_forbidden(ipaddress.ip_address("::ffff:10.0.0.1"))[0] is True


def test_is_ip_allowed_public_ips() -> None:
    # Public non-reserved IPs should not be forbidden
    assert is_ip_forbidden(ipaddress.ip_address("93.184.216.34"))[0] is False
    assert is_ip_forbidden(ipaddress.ip_address("8.8.8.8"))[0] is False
    assert is_ip_forbidden(ipaddress.ip_address("1.1.1.1"))[0] is False
    assert is_ip_forbidden(ipaddress.ip_address("2606:4700:4700::1111"))[0] is False


def test_validate_url_ssrf_schemes() -> None:
    with pytest.raises(SSRFProtectionError, match=r"disallowed URL scheme 'file'"):
        validate_url_ssrf_safe("file:///etc/passwd", resolve_dns=False)

    with pytest.raises(SSRFProtectionError, match=r"disallowed URL scheme 'ftp'"):
        validate_url_ssrf_safe("ftp://example.com/file.txt", resolve_dns=False)

    with pytest.raises(SSRFProtectionError, match=r"disallowed URL scheme 'gopher'"):
        validate_url_ssrf_safe("gopher://127.0.0.1:70", resolve_dns=False)


def test_validate_url_ssrf_blocked_hostnames() -> None:
    with pytest.raises(SSRFProtectionError, match=r"local/metadata hostname 'localhost'"):
        validate_url_ssrf_safe("http://localhost/admin", resolve_dns=False)

    with pytest.raises(SSRFProtectionError, match=r"local/metadata hostname 'evil.localhost'"):
        validate_url_ssrf_safe("http://evil.localhost/feed", resolve_dns=False)

    with pytest.raises(SSRFProtectionError, match=r"metadata\.google\.internal"):
        validate_url_ssrf_safe(
            "http://metadata.google.internal/computeMetadata/v1", resolve_dns=False
        )


def test_validate_url_ssrf_literal_forbidden_ips() -> None:
    with pytest.raises(SSRFProtectionError, match=r"blocked by SSRF protection: loopback"):
        validate_url_ssrf_safe("http://127.0.0.1:8080/secret", resolve_dns=False)

    with pytest.raises(SSRFProtectionError, match=r"cloud metadata"):
        validate_url_ssrf_safe("http://169.254.169.254/latest/meta-data", resolve_dns=False)

    with pytest.raises(SSRFProtectionError, match=r"private RFC 1918"):
        validate_url_ssrf_safe("http://192.168.1.100/config", resolve_dns=False)


def test_validate_url_ssrf_rejects_malformed_port() -> None:
    with pytest.raises(ValidationError, match="invalid URL port"):
        validate_url_ssrf_safe("http://example.com:not-a-port/path", resolve_dns=True)


def test_validate_url_ssrf_dns_resolution_blocking() -> None:
    # Mock DNS resolving to internal IP
    with patch("socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (2, 1, 6, "", ("10.0.0.5", 80)),
        ]
        with pytest.raises(SSRFProtectionError, match=r"resolved to forbidden IP '10\.0\.0\.5'"):
            validate_url_ssrf_safe("http://attacker-controlled-domain.test/log", resolve_dns=True)


@pytest.mark.asyncio
async def test_safe_http_fetcher_blocks_redirect_to_metadata() -> None:
    fetcher = SafeHTTPFetcher()

    # Attempting to fetch a direct metadata URL is caught immediately
    with pytest.raises(SSRFProtectionError, match="cloud metadata"):
        await fetcher.fetch_url("http://169.254.169.254/latest/meta-data")


@pytest.mark.asyncio
async def test_safe_http_fetcher_blocks_empty_or_malformed_urls() -> None:
    fetcher = SafeHTTPFetcher()
    with pytest.raises(ValidationError, match="URL must not be empty"):
        await fetcher.fetch_url("")

    with pytest.raises(SSRFProtectionError, match="disallowed URL scheme"):
        await fetcher.fetch_url("javascript:alert(1)")


@pytest.mark.asyncio
async def test_safe_http_fetcher_uses_pinned_ip_transport() -> None:
    from unittest.mock import AsyncMock, MagicMock, patch

    from acip.core.security.ssrf import PinnedIPTransport, SafeHTTPFetcher, _PinnedIPNetworkBackend

    backend = _PinnedIPNetworkBackend("93.184.216.34")
    assert backend._pinned_ip == "93.184.216.34"

    transport = PinnedIPTransport("93.184.216.34")
    assert isinstance(transport._pool._network_backend, _PinnedIPNetworkBackend)
    assert transport._pool._network_backend._pinned_ip == "93.184.216.34"

    fetcher = SafeHTTPFetcher()
    with (
        patch("acip.core.security.ssrf.validate_url_ssrf_safe") as mock_validate,
        patch("httpx.AsyncClient") as mock_client,
    ):
        mock_validate.return_value = ("http://safe-domain.example/data", ["93.184.216.34"])
        mock_ctx = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_ctx)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}

        async def fake_iter() -> Any:
            yield b"safe content"

        mock_resp.aiter_bytes = fake_iter

        mock_stream = MagicMock()
        mock_stream.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_stream.__aexit__ = AsyncMock(return_value=None)
        mock_ctx.stream.return_value = mock_stream

        result = await fetcher.fetch_url("http://safe-domain.example/data")
        assert result.content == b"safe content"

        mock_client.assert_called_once()
        transport_arg = mock_client.call_args[1].get("transport")
        assert isinstance(transport_arg, PinnedIPTransport)
        assert isinstance(transport_arg._pool._network_backend, _PinnedIPNetworkBackend)
        assert transport_arg._pool._network_backend._pinned_ip == "93.184.216.34"
