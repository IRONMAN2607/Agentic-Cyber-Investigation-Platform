"""Deterministic indicator-of-compromise extraction.

IOC extraction is done with regular expressions and validators rather than an
LLM. Two reasons: it is the part of triage where correctness is objectively
checkable, and making it deterministic means extraction accuracy can be measured
against ground truth in the evaluation harness without model variance.

Every candidate is validated after matching (``ipaddress`` for addresses, length
and charset for hashes, a file-extension denylist for domains), so the output is
checkable rather than merely plausible.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from acip.core.evidence.contracts import EntityRef, EvidenceDraft
from acip.errors import ToolError
from acip.tools.base import ToolAdapter, ToolContext, ToolResult
from acip.types import EntityType, EvidenceKind, SandboxTier, TimeConfidence

_PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\]\)}]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,63}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6": re.compile(r"(?<![:.\w])(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}(?![:.\w])"),
    "domain": re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
    ),
}

# Order matters: longer/more specific types are extracted first and their spans
# are masked, so a hash is not re-reported as three shorter hashes and a URL's
# host is not double-counted as a bare domain.
_EXTRACTION_ORDER = ("url", "email", "sha256", "sha1", "md5", "ipv6", "ipv4", "domain")

_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}

# `server.log` and `payload.exe` both satisfy the domain grammar. Rejecting a
# known set of file extensions removes the dominant false-positive class; it is a
# documented heuristic, recorded on the evidence as such.
_FILE_EXTENSIONS = frozenset(
    """exe dll sys bat cmd ps1 sh py rb pl php jsp asp aspx jar class so dylib
    log txt md conf config cfg ini yaml yml json xml csv tsv sql db sqlite bak
    old tmp temp lock pid socket service key pem crt cer pfx p12 zip tar gz bz2
    xz rar 7z iso img bin dat dmp core pcap pcapng evtx doc docx xls xlsx ppt
    pptx pdf rtf odt jpg jpeg png gif bmp svg ico mp3 mp4 avi mkv html htm css
    js ts tsx jsx map min lnk url scr vbs wsf reg""".split()
)

_DEFANG_SUBSTITUTIONS = (
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("fxp", "ftp"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("[:]", ":"),
    ("[at]", "@"),
    ("[@]", "@"),
)

_ENTITY_FOR_IOC: dict[str, EntityType] = {
    "url": EntityType.URL,
    "email": EntityType.EMAIL,
    "domain": EntityType.DOMAIN,
    "ipv4": EntityType.IP,
    "ipv6": EntityType.IP,
    "md5": EntityType.HASH,
    "sha1": EntityType.HASH,
    "sha256": EntityType.HASH,
}

# Domains are grammar-matched rather than resolved, so they carry lower
# confidence than a validated address or a fixed-length hash.
_CONFIDENCE = {"domain": 0.8, "email": 0.9}
_CONTEXT_WINDOW = 60
_MAX_TEXT_CHARS = 8 * 1024 * 1024


class IOCExtractorArgs(BaseModel):
    """Options for extraction.

    ``text`` lets a caller scan a short string such as the investigation target.
    When omitted, the artifact supplied in the tool context is scanned.
    """

    text: str | None = Field(default=None, max_length=_MAX_TEXT_CHARS)
    max_iocs: int = Field(default=5_000, ge=1, le=100_000)
    include_non_global_ips: bool = Field(
        default=True,
        description="Keep private/loopback addresses. They are weak IOCs but real evidence.",
    )


class IOCExtractor(ToolAdapter):
    """Extracts and validates indicators from text."""

    name: ClassVar[str] = "ioc_extractor"
    version: ClassVar[str] = "1.0.0"
    tier: ClassVar[SandboxTier] = SandboxTier.T0_IN_PROCESS
    args_model: ClassVar[type[BaseModel]] = IOCExtractorArgs
    description: ClassVar[str] = (
        "Extracts IPs, domains, URLs, hashes and emails from text with validation."
    )
    requires_artifact: ClassVar[bool] = False

    async def execute(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, IOCExtractorArgs)

        if args.text is not None:
            text, lossy = args.text, False
        elif ctx.artifact_path is not None:
            from acip.core.security.files import read_text

            text, lossy = read_text(ctx.artifact_path)
        else:
            raise ToolError(f"{self.name} requires either 'text' or an artifact")

        return self.extract(text, args, lossy=lossy)

    def extract(self, text: str, args: IOCExtractorArgs, *, lossy: bool = False) -> ToolResult:
        """Extract indicators from ``text``. Directly testable."""
        warnings: list[str] = []
        if lossy:
            warnings.append("artifact was not valid UTF-8; decoded as latin-1")

        refanged, defanged_input = _refang(text)
        # Mask consumed spans so broader patterns cannot re-match narrower hits.
        masked = list(refanged)
        found: dict[tuple[str, str], dict[str, Any]] = {}
        rejected: dict[str, int] = {}
        truncated = False

        for ioc_type in _EXTRACTION_ORDER:
            if truncated:
                break
            for match in _PATTERNS[ioc_type].finditer("".join(masked)):
                raw_value = match.group(0)
                validated = _validate(ioc_type, raw_value, args)
                if validated is None:
                    rejected[ioc_type] = rejected.get(ioc_type, 0) + 1
                    continue
                value, extra = validated

                key = (ioc_type, value)
                if key not in found:
                    if len(found) >= args.max_iocs:
                        truncated = True
                        break
                    found[key] = {
                        "ioc_type": ioc_type,
                        "value": value,
                        "occurrences": 0,
                        "context": _context(refanged, match.start(), match.end()),
                        "defanged_in_source": defanged_input,
                        **extra,
                    }
                found[key]["occurrences"] += 1
                for index in range(match.start(), match.end()):
                    masked[index] = "\x00"

        if truncated:
            warnings.append(f"extraction truncated at max_iocs={args.max_iocs}")
        for ioc_type, count in sorted(rejected.items()):
            warnings.append(f"{count} {ioc_type} candidate(s) rejected by validation")

        evidence = [self._to_evidence(record) for record in found.values()]
        counts: dict[str, int] = {}
        for (ioc_type, _), _record in found.items():
            counts[ioc_type] = counts.get(ioc_type, 0) + 1

        return ToolResult(
            evidence=evidence,
            metrics={
                "characters_scanned": len(refanged),
                "iocs_found": len(found),
                "iocs_by_type": counts,
                "candidates_rejected": rejected,
                "defanged_input": defanged_input,
            },
            warnings=warnings,
            exit_status=0,
        )

    @staticmethod
    def _to_evidence(record: dict[str, Any]) -> EvidenceDraft:
        ioc_type = str(record["ioc_type"])
        entity_type = _ENTITY_FOR_IOC[ioc_type]
        return EvidenceDraft(
            kind=EvidenceKind.IOC,
            data=record,
            observed_at=None,
            # An indicator has no intrinsic time; the events that reference it do.
            time_confidence=TimeConfidence.UNKNOWN,
            entities=[EntityRef(type=entity_type, value=str(record["value"]), role="indicator")],
            confidence=_CONFIDENCE.get(ioc_type, 1.0),
        )


def _refang(text: str) -> tuple[str, bool]:
    """Undo common defanging so indicators can be matched."""
    result = text
    changed = False
    for needle, replacement in _DEFANG_SUBSTITUTIONS:
        if needle in result or needle.upper() in result:
            pattern = re.compile(re.escape(needle), re.IGNORECASE)
            result, count = pattern.subn(replacement, result)
            changed = changed or count > 0
    return result, changed


def _validate(
    ioc_type: str, value: str, args: IOCExtractorArgs
) -> tuple[str, dict[str, Any]] | None:
    """Return the canonical value plus extra fields, or ``None`` to reject."""
    match ioc_type:
        case "ipv4" | "ipv6":
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                return None
            scope = _ip_scope(address)
            if scope != "global" and not args.include_non_global_ips:
                return None
            return str(address), {"ip_version": address.version, "scope": scope}

        case "md5" | "sha1" | "sha256":
            if len(value) != _HASH_LENGTHS[ioc_type]:
                return None
            return value.lower(), {"hash_algorithm": ioc_type}

        case "domain":
            candidate = value.rstrip(".").lower()
            label = candidate.rsplit(".", 1)
            if len(label) != 2:
                return None
            tld = label[1]
            if tld in _FILE_EXTENSIONS:
                return None
            try:  # A dotted quad is an address, not a domain.
                ipaddress.ip_address(candidate)
                return None
            except ValueError:
                pass
            try:
                candidate.encode("idna")
            except UnicodeError:
                return None
            return candidate, {"validation": "grammar_and_extension_denylist"}

        case "url":
            trimmed = value.rstrip(".,;:!?)")
            scheme, _, remainder = trimmed.partition("://")
            if not remainder:
                return None
            host = remainder.split("/", 1)[0].split("@")[-1].split(":")[0]
            if not host:
                return None
            return f"{scheme.lower()}://{remainder}", {"url_host": host.lower()}

        case "email":
            local, _, domain = value.rpartition("@")
            if not local or not domain:
                return None
            return value.lower(), {"email_domain": domain.lower()}

    return None


def _ip_scope(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Classify an address. Non-global addresses are weak indicators."""
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved or address.is_unspecified:
        return "reserved"
    return "global"


def _context(text: str, start: int, end: int) -> str:
    """A short surrounding excerpt, for the evidence viewer."""
    left = max(0, start - _CONTEXT_WINDOW)
    right = min(len(text), end + _CONTEXT_WINDOW)
    excerpt = text[left:right].replace("\n", " ").replace("\r", " ")
    return excerpt.strip()
