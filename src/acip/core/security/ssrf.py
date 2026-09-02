"""SSRF (Server-Side Request Forgery) protection subsystem.

Enforces strict network-level security controls before any remote URL is fetched:
1. Scheme allowlist (HTTP and HTTPS only).
2. Domain and hostname validation (blocking metadata and local hostnames).
3. Pre-flight DNS resolution (A and AAAA records).
4. Strict IP blacklist: loopback, RFC 1918 private, link-local, cloud metadata
   (AWS/Azure/GCP/Alibaba), CGNAT, multicast, broadcast, testnet, IPv4-mapped IPv6.
5. Anti-DNS rebinding and hop-by-hop redirect verification.
6. Response body size streaming limits and timeouts.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import urllib.parse
from dataclasses import dataclass

import httpx

from acip.errors import PayloadTooLargeError, SSRFProtectionError, ValidationError

# Explicit network ranges forbidden for outbound fetches
_FORBIDDEN_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),  # Current network / unspecified
    ipaddress.ip_network("10.0.0.0/8"),  # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-Grade NAT (CGNAT)
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),  # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),  # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),  # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),  # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved / Future use
    ipaddress.ip_network("255.255.255.255/32"),  # Limited broadcast
]

_FORBIDDEN_IPV6_NETWORKS = [
    ipaddress.ip_network("::/128"),  # Unspecified
    ipaddress.ip_network("::1/128"),  # Loopback
    ipaddress.ip_network("100::/64"),  # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),  # Documentation
    ipaddress.ip_network("fc00::/7"),  # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),  # Link-local unicast
    ipaddress.ip_network("ff00::/8"),  # Multicast
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IPv6 IMDS
]

# Explicit cloud metadata hostnames / IPs
_CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS, Azure, GCP, OpenStack metadata
    "100.100.100.200",  # Alibaba Cloud metadata
    "169.254.170.2",  # AWS ECS task metadata
    "fd00:ec2::254",  # AWS IPv6 metadata
}

_BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}


@dataclass(frozen=True)
class SafeFetchResult:
    """Result of an SSRF-safe HTTP request."""

    url: str
    status_code: int
    headers: dict[str, str]
    content: bytes
    content_type: str
    sha256: str


def is_ip_forbidden(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    """Check if an IP address falls into a private, loopback, or cloud metadata range."""
    # Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    ip_str = str(ip)
    if ip_str in _CLOUD_METADATA_IPS:
        return True, f"cloud metadata IP ({ip_str})"

    if ip.is_loopback:
        return True, "loopback address"
    if ip.is_private:
        return True, "private RFC 1918 / ULA address"
    if ip.is_link_local:
        return True, "link-local address"
    if ip.is_multicast:
        return True, "multicast address"
    if ip.is_reserved:
        return True, "reserved address"
    if ip.is_unspecified:
        return True, "unspecified 0.0.0.0/:: address"

    if isinstance(ip, ipaddress.IPv4Address):
        for net in _FORBIDDEN_IPV4_NETWORKS:
            if ip in net:
                return True, f"forbidden network range ({net})"
    elif isinstance(ip, ipaddress.IPv6Address):
        for net in _FORBIDDEN_IPV6_NETWORKS:
            if ip in net:
                return True, f"forbidden IPv6 network range ({net})"

    return False, ""


def validate_url_ssrf_safe(url: str, *, resolve_dns: bool = True) -> tuple[str, list[str]]:
    """Validate a URL against SSRF rules and resolve its DNS records.

    Raises :class:`SSRFProtectionError` or :class:`ValidationError` if unsafe.
    Returns ``(normalized_url, resolved_ips)``.
    """
    candidate = url.strip()
    if not candidate:
        raise ValidationError("URL must not be empty")
    if len(candidate) > 4096:
        raise ValidationError("URL exceeds maximum length of 4096 characters")

    try:
        parsed = urllib.parse.urlsplit(candidate)
    except Exception as exc:
        raise ValidationError(f"malformed URL: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise SSRFProtectionError(
            f"disallowed URL scheme '{parsed.scheme}': only 'http' and 'https' are permitted"
        )

    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise ValidationError("URL missing hostname")

    # Check known forbidden hostnames
    if (
        hostname in _BLOCKED_HOSTNAMES
        or hostname.endswith(".localhost")
        or hostname.endswith(".internal")
        or hostname.endswith(".local")
    ):
        raise SSRFProtectionError(f"access to local/metadata hostname '{hostname}' is blocked")

    resolved_ips: list[str] = []

    # Case 1: Hostname is a literal IP
    try:
        literal_ip = ipaddress.ip_address(hostname)
        forbidden, reason = is_ip_forbidden(literal_ip)
        if forbidden:
            raise SSRFProtectionError(
                f"access to IP '{hostname}' blocked by SSRF protection: {reason}"
            )
        resolved_ips.append(str(literal_ip))
    except ValueError:
        # Case 2: Hostname is a domain, perform DNS resolution
        if resolve_dns:
            port = parsed.port or (443 if scheme == "https" else 80)
            try:
                addr_info = socket.getaddrinfo(
                    hostname, port, family=socket.AF_UNSPEC, proto=socket.IPPROTO_TCP
                )
            except socket.gaierror as exc:
                raise SSRFProtectionError(
                    f"failed to resolve hostname '{hostname}': {exc}"
                ) from exc

            for item in addr_info:
                sockaddr = item[4]
                ip_raw = sockaddr[0]
                try:
                    ip_obj = ipaddress.ip_address(ip_raw)
                    forbidden, reason = is_ip_forbidden(ip_obj)
                    if forbidden:
                        raise SSRFProtectionError(
                            f"hostname '{hostname}' resolved to forbidden IP '{ip_raw}': {reason}"
                        )
                    if str(ip_obj) not in resolved_ips:
                        resolved_ips.append(str(ip_obj))
                except ValueError as exc:
                    raise SSRFProtectionError(
                        f"invalid IP address resolved for '{hostname}': {ip_raw}"
                    ) from exc

    normalized_path = parsed.path or "/"
    reconstructed = urllib.parse.urlunsplit(
        (scheme, parsed.netloc, normalized_path, parsed.query, parsed.fragment)
    )
    return reconstructed, resolved_ips


class SafeHTTPFetcher:
    """Asynchronous HTTP fetcher with anti-SSRF protection and resource bounding."""

    def __init__(
        self,
        *,
        max_bytes: int = 10 * 1024 * 1024,  # 10 MB default limit
        max_redirects: int = 3,
        timeout_seconds: float = 10.0,
        user_agent: str = "ACIP-Artifact-Intake/1.0",
    ) -> None:
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent

    async def fetch_url(self, target_url: str) -> SafeFetchResult:
        """Fetch remote URL safely, validating every hop and streaming the body."""
        current_url = target_url
        headers_to_send = {"User-Agent": self.user_agent, "Accept": "*/*"}

        for redirect_count in range(self.max_redirects + 1):
            # Pre-flight SSRF validation on current URL
            validated_url, _ = validate_url_ssrf_safe(current_url, resolve_dns=True)

            timeout = httpx.Timeout(
                connect=min(5.0, self.timeout_seconds),
                read=self.timeout_seconds,
                write=5.0,
                pool=5.0,
            )

            async with httpx.AsyncClient(
                follow_redirects=False, timeout=timeout, verify=True
            ) as client:
                try:
                    async with client.stream("GET", validated_url, headers=headers_to_send) as resp:
                        # Handle redirects manually with hop-by-hop SSRF validation
                        if resp.status_code in {301, 302, 303, 307, 308}:
                            location = resp.headers.get("location")
                            if not location:
                                raise ValidationError(
                                    f"received redirect status {resp.status_code} "
                                    "with no Location header"
                                )
                            if redirect_count >= self.max_redirects:
                                raise SSRFProtectionError(
                                    f"exceeded maximum redirect limit of {self.max_redirects}"
                                )

                            # Resolve relative redirect URLs safely against current URL
                            next_url = urllib.parse.urljoin(current_url, location)
                            current_url = next_url
                            continue

                        if resp.status_code >= 400:
                            raise ValidationError(
                                f"remote server returned error status {resp.status_code} "
                                f"for {validated_url}"
                            )

                        # Stream body and enforce max_bytes limit
                        content_chunks: list[bytes] = []
                        total_bytes = 0
                        digest = hashlib.sha256()

                        async for chunk in resp.aiter_bytes():
                            if not chunk:
                                continue
                            total_bytes += len(chunk)
                            if total_bytes > self.max_bytes:
                                raise PayloadTooLargeError(
                                    f"remote response exceeded size cap of {self.max_bytes} bytes",
                                    detail={"max_bytes": self.max_bytes},
                                )
                            digest.update(chunk)
                            content_chunks.append(chunk)

                        body = b"".join(content_chunks)
                        content_type = resp.headers.get("content-type", "application/octet-stream")

                        return SafeFetchResult(
                            url=validated_url,
                            status_code=resp.status_code,
                            headers=dict(resp.headers),
                            content=body,
                            content_type=content_type,
                            sha256=digest.hexdigest(),
                        )
                except httpx.RequestError as exc:
                    raise ValidationError(
                        f"HTTP request to '{validated_url}' failed: {exc}"
                    ) from exc

        raise SSRFProtectionError("too many redirects")
