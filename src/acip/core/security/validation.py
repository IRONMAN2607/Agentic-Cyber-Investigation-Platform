"""Input and indicator validation primitives.

Provides strict, deterministic validation and canonicalization for investigation
targets, indicators, and artifact metadata (IP addresses, domain names, URLs,
hashes, files, logs, and PCAPs).
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import urllib.parse

from acip.errors import ValidationError
from acip.types import TargetType

# Standard hexadecimal hashes
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SHA512_RE = re.compile(r"^[0-9a-fA-F]{128}$")

# Domain label regex (RFC 1035 / RFC 1123)
_DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def _undefang(value: str) -> str:
    """Normalize defanged indicators and strip enclosing formatting quotes."""
    cleaned = value.strip().strip("'\"<>")
    return cleaned.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def validate_ip(value: str) -> str:
    """Validate and canonicalize an IPv4 or IPv6 address string.

    Tolerates defanging (e.g. 1.2.3[.]4), ports, protocol schemes, and CIDRs.
    Returns the canonical string representation.
    """
    candidate = _undefang(value)
    if not candidate:
        raise ValidationError("IP address must not be empty")

    # If full URL pasted into IP field, extract hostname
    if "://" in candidate:
        with contextlib.suppress(Exception):
            parsed = urllib.parse.urlsplit(candidate)
            candidate = parsed.hostname or candidate

    # IPv6 with port: [2001:db8::1]:8080
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif ":" in candidate and candidate.count(":") == 1:
        # IPv4 with port: 198.51.100.23:8080
        candidate = candidate.split(":", 1)[0]

    # CIDR network notation: 198.51.100.0/24 -> 198.51.100.0
    if "/" in candidate:
        with contextlib.suppress(ValueError):
            net = ipaddress.ip_network(candidate, strict=False)
            return str(net.network_address)

    try:
        addr = ipaddress.ip_address(candidate)
        return str(addr)
    except ValueError as exc:
        raise ValidationError(f"invalid IP address '{value}': {exc}") from exc


def validate_hash(value: str) -> str:
    """Validate a cryptographic hash (MD5, SHA-1, SHA-256, or SHA-512).

    Tolerates algorithm prefixes (e.g. md5:, sha256:) and casing.
    Returns the lowercase normalized hash string.
    """
    candidate = _undefang(value).lower()
    if not candidate:
        raise ValidationError("hash must not be empty")

    candidate = re.sub(
        r"^(?:md5|sha1|sha256|sha512|hash)\s*:\s*", "", candidate, flags=re.IGNORECASE
    )

    if (
        _MD5_RE.match(candidate)
        or _SHA1_RE.match(candidate)
        or _SHA256_RE.match(candidate)
        or _SHA512_RE.match(candidate)
    ):
        return candidate

    raise ValidationError(
        f"invalid cryptographic hash '{value}': must be 32 (MD5), 40 (SHA-1), "
        "64 (SHA-256), or 128 (SHA-512) hexadecimal characters"
    )


def validate_domain(value: str) -> str:
    """Validate and canonicalize a fully qualified domain name.

    Tolerates defanging (e.g. evil[.]com), full URLs, ports, and trailing slashes.
    Returns the lowercased domain with trailing dot stripped.
    """
    candidate = _undefang(value)
    if not candidate:
        raise ValidationError("domain name must not be empty")

    # Normalize defanged protocols if present
    candidate = re.sub(r"^hxxps?://", "http://", candidate, flags=re.IGNORECASE)

    # If full URL pasted, extract hostname
    if "://" in candidate:
        with contextlib.suppress(Exception):
            parsed = urllib.parse.urlsplit(candidate)
            candidate = parsed.hostname or candidate

    # Strip paths or queries if entered like evil.com/login?foo=1
    if "/" in candidate:
        candidate = candidate.split("/", 1)[0]

    # Strip port if present
    if ":" in candidate:
        candidate = candidate.split(":", 1)[0]

    candidate = candidate.strip().rstrip(".").lower()
    if not candidate:
        raise ValidationError("domain name must not be empty")
    if len(candidate) > 253:
        raise ValidationError(f"domain name exceeds maximum length of 253 characters: {candidate}")

    labels = candidate.split(".")
    if len(labels) < 2 and candidate != "localhost":
        raise ValidationError(f"domain name must contain at least two labels: '{candidate}'")

    for label in labels:
        if not label or len(label) > 63:
            raise ValidationError(f"invalid domain label '{label}' in '{candidate}'")
        if not _DOMAIN_LABEL_RE.match(label):
            raise ValidationError(
                f"domain label '{label}' contains invalid characters in '{candidate}'"
            )

    return candidate


def validate_url(value: str) -> str:
    """Validate and canonicalize a URL structure.

    Tolerates URLs without schemes (defaults to https://), defanged schemes (hxxp://, hxxps://),
    and normalizes path and casing. Enforces RFC 3986 compliance and http/https scheme allowlist.
    """
    candidate = _undefang(value)
    if not candidate:
        raise ValidationError("URL must not be empty")
    if len(candidate) > 4096:
        raise ValidationError("URL exceeds maximum length of 4096 characters")

    # Normalize defanged protocols
    if re.match(r"^hxxps?://", candidate, re.IGNORECASE):
        candidate = re.sub(r"^hxxp", "http", candidate, flags=re.IGNORECASE)

    # Prepend scheme if missing (e.g. evil-domain.com/path or google.com)
    if "://" not in candidate:
        if candidate.startswith("//"):
            candidate = "https:" + candidate
        else:
            candidate = "https://" + candidate

    # Reject null bytes and raw whitespace/control characters
    if any(ord(c) < 32 or ord(c) == 127 for c in candidate):
        raise ValidationError("URL contains illegal control characters")

    try:
        parsed = urllib.parse.urlsplit(candidate)
    except Exception as exc:
        raise ValidationError(f"malformed URL '{candidate}': {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValidationError(
            f"disallowed URL scheme '{parsed.scheme}': only 'http' and 'https' are permitted"
        )

    if not parsed.netloc:
        raise ValidationError(f"URL missing valid network host: '{candidate}'")

    hostname = parsed.hostname
    if not hostname:
        raise ValidationError(f"URL missing hostname: '{candidate}'")

    # Validate port range if specified
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValidationError(f"invalid port number '{parsed.port}' in URL")

    # Reconstruct normalized URL
    netloc = hostname.lower()
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        netloc = f"{userinfo}@{netloc}"

    normalized_path = parsed.path or "/"
    rebuilt = urllib.parse.urlunsplit(
        (scheme, netloc, normalized_path, parsed.query, parsed.fragment)
    )
    return rebuilt


def validate_target_value(target_type: TargetType, value: str) -> str:
    """Validate and canonicalize a target value for investigation creation."""
    stripped = value.strip()
    if not stripped:
        raise ValidationError("target value must not be blank")

    match target_type:
        case TargetType.IP:
            return validate_ip(stripped)
        case TargetType.HASH:
            return validate_hash(stripped)
        case TargetType.DOMAIN:
            return validate_domain(stripped)
        case TargetType.URL:
            return validate_url(stripped)
        case TargetType.LOG | TargetType.FILE | TargetType.PCAP | TargetType.DESCRIPTION:
            # File, log, PCAP, and incident descriptions are bounded strings
            if len(stripped) > 4096:
                raise ValidationError(
                    f"target value exceeds 4096 characters for {target_type.value}"
                )
            return stripped
        case _:
            return stripped
