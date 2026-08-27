"""Network security and SSRF protection.

Strict SSRF controls enforcing that untrusted target URLs or outbound lookups
cannot target localhost, private subnets, cloud instance metadata services
(169.254.169.254), or reserved ranges.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from acip.errors import ValidationError

# Forbidden IPv4 networks
_BLOCKED_IPV4_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),  # Current network
    ipaddress.ip_network("10.0.0.0/8"),  # RFC1918 Private
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local & Cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),  # RFC1918 Private
    ipaddress.ip_network("192.168.0.0/16"),  # RFC1918 Private
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
)

# Forbidden IPv6 networks
_BLOCKED_IPV6_NETWORKS = (
    ipaddress.ip_network("::1/128"),  # Loopback
    ipaddress.ip_network("fc00::/7"),  # Unique Local Address
    ipaddress.ip_network("fe80::/10"),  # Link-local
    ipaddress.ip_network("ff00::/8"),  # Multicast
)


def validate_url_safe(url: str) -> str:
    """Validate a URL against SSRF attacks and forbidden targets.

    Raises :class:`~acip.errors.ValidationError` if the URL scheme is invalid,
    the hostname is missing or resolves to a private/loopback/metadata IP.
    """
    if not url or not url.strip():
        raise ValidationError("URL cannot be empty")

    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValidationError(
            f"invalid URL scheme: {parsed.scheme!r}; only http and https are allowed"
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValidationError("URL must contain a valid hostname")

    # Reject userinfo in URL (e.g. http://user:pass@host)
    if parsed.username or parsed.password:
        raise ValidationError("URL userinfo credentials are not permitted")

    # Reject literal localhost or loopback names
    if hostname.lower() in {"localhost", "localhost.localdomain"}:
        raise ValidationError("URL cannot target localhost")

    # Resolve IP addresses
    try:
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValidationError(f"could not resolve hostname: {hostname}") from exc

    if not addr_info:
        raise ValidationError(f"no IP address found for host: {hostname}")

    for entry in addr_info:
        ip_str = entry[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise ValidationError(f"invalid IP address: {ip_str}") from exc

        if isinstance(ip_obj, ipaddress.IPv4Address):
            for blocked in _BLOCKED_IPV4_NETWORKS:
                if ip_obj in blocked:
                    raise ValidationError(
                        f"URL targets blocked private/reserved IP: {ip_str} ({blocked})"
                    )
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            for blocked in _BLOCKED_IPV6_NETWORKS:
                if ip_obj in blocked:
                    raise ValidationError(
                        f"URL targets blocked private/reserved IPv6: {ip_str} ({blocked})"
                    )

    return url
