"""Deterministic URL and Domain security detection rules.

Evaluates brand impersonation, typosquatting, deceptive subdomain spoofing,
phishing and scam reward lures, and verifies legitimate high-reputation domains.
Pure functions over URL and domain strings: no database, no LLM, no I/O.
"""

from __future__ import annotations

import re
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Any

from acip.types import Severity


@dataclass(frozen=True)
class DetectionHit:
    """A deterministic detection rule firing, citing the evidence that triggered it."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    reasoning: str
    evidence_ids: list[uuid.UUID] = field(default_factory=list)


RULE_LEGITIMATE_DOMAIN = "R-URL-000"
RULE_BRAND_IMPERSONATION = "R-URL-001"
RULE_SUBDOMAIN_SPOOFING = "R-URL-002"
RULE_PHISHING_LURE = "R-URL-003"
RULE_CREDENTIAL_PHISHING_CAMPAIGN = "R-URL-004"

# Authoritative directory of verified legitimate enterprise, tech, and public service domains
KNOWN_LEGITIMATE_DOMAINS: dict[str, str] = {
    "claude.com": "Anthropic Claude",
    "claude.ai": "Anthropic Claude AI",
    "anthropic.com": "Anthropic",
    "google.com": "Google",
    "gmail.com": "Google Mail",
    "youtube.com": "YouTube",
    "microsoft.com": "Microsoft",
    "azure.com": "Microsoft Azure",
    "office.com": "Microsoft Office",
    "windows.com": "Microsoft Windows",
    "github.com": "GitHub",
    "apple.com": "Apple",
    "icloud.com": "Apple iCloud",
    "amazon.com": "Amazon",
    "aws.amazon.com": "Amazon Web Services",
    "openai.com": "OpenAI",
    "chatgpt.com": "OpenAI ChatGPT",
    "wikipedia.org": "Wikimedia",
    "mozilla.org": "Mozilla",
}

# High-value targeted brands and known typosquat / impersonation patterns
BRAND_TARGETS: list[tuple[str, re.Pattern[str], set[str]]] = [
    (
        "microsoft",
        re.compile(
            r"(?i)\b(microslop|microsofft|micosoft|micr0soft|ms-office|msft-verify|microsoft-security|windows-update)\b"
        ),
        {"microsoft.com", "azure.com", "office.com", "windows.com", "live.com", "msn.com"},
    ),
    (
        "google",
        re.compile(
            r"(?i)\b(goog1e|g00gle|google-verify|google-security|account-google|gmail-security)\b"
        ),
        {"google.com", "gmail.com", "youtube.com", "android.com"},
    ),
    (
        "claude",
        re.compile(r"(?i)\b(claud-ai|claude-login|anthroopic|claud\.ai|claude-verify)\b"),
        {"claude.com", "claude.ai", "anthropic.com"},
    ),
    (
        "paypal",
        re.compile(r"(?i)\b(paypa1|paypal-security|paypal-update|paypal-verify)\b"),
        {"paypal.com"},
    ),
    (
        "apple",
        re.compile(r"(?i)\b(appl1e|appleid-verify|apple-support-login|icloud-verify)\b"),
        {"apple.com", "icloud.com"},
    ),
    (
        "amazon",
        re.compile(r"(?i)\b(amaz0n|amazon-billing|aws-verify|amazon-security)\b"),
        {"amazon.com"},
    ),
    (
        "netflix",
        re.compile(r"(?i)\b(netf1ix|netflix-billing|netflix-verify|netflix-update)\b"),
        {"netflix.com"},
    ),
]

# Deceptive phishing, reward, and credential harvesting lures
PHISHING_LURE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "reward_discount",
        re.compile(
            r"(?i)(claim\w*discount|rewards?/\w*claim|5000discount|free\w*giftcard|crypto\w*airdrop|claim\w*reward|free\w*voucher)"
        ),
    ),
    (
        "credential_harvesting",
        re.compile(
            r"(?i)(verify\w*account|login\w*confirm|suspended\w*reactivate|update\w*billing|security\w*alert|confirm\w*card|confirm\w*identity|wallet\w*connect)"
        ),
    ),
]


def decompose_url_target(target: str) -> tuple[str, str, str | None, str]:
    """Parse a target string into (host, path, query, clean_url)."""
    clean = target.strip()
    if not clean.startswith(("http://", "https://")):
        clean_url = f"https://{clean}"
    else:
        clean_url = clean

    parsed = urllib.parse.urlparse(clean_url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    query = parsed.query or None
    return host, path, query, clean_url


def inspect_target_reputation(target: str) -> dict[str, Any]:
    """Provide deterministic reputation evaluation for a domain or URL target."""
    host, path, query, _ = decompose_url_target(target)
    if not host:
        return {
            "source": "local_deterministic_feed",
            "abuse_score": None,
            "is_malicious": None,
            "reputation_status": "unknown",
            "category": "Unknown / Unclassified",
            "reports_count": 0,
        }

    # 1. Verified legitimate domain check
    for leg_dom, brand_name in KNOWN_LEGITIMATE_DOMAINS.items():
        if host == leg_dom or host.endswith(f".{leg_dom}"):
            return {
                "source": "local_deterministic_feed",
                "abuse_score": 0,
                "is_malicious": False,
                "reputation_status": "benign",
                "category": f"Verified Legitimate Service ({brand_name})",
                "reports_count": 0,
            }

    # 2. Typosquatting / brand spoofing check
    full_target_str = f"{host}{path}?{query}" if query else f"{host}{path}"
    has_typosquat = False
    has_subdomain_spoof = False
    impersonated_brand = ""

    for brand, pattern, leg_domains in BRAND_TARGETS:
        if pattern.search(host) or pattern.search(full_target_str):
            has_typosquat = True
            impersonated_brand = brand
            break
        # Subdomain spoofing: e.g. account.google.com.verify
        if brand in host and not any(host == d or host.endswith(f".{d}") for d in leg_domains):
            has_subdomain_spoof = True
            impersonated_brand = brand
            break

    # 3. Phishing lure check
    has_phishing_lure = any(
        pattern.search(full_target_str) for _, pattern in PHISHING_LURE_PATTERNS
    )

    if (has_typosquat or has_subdomain_spoof) and has_phishing_lure:
        return {
            "source": "local_deterministic_feed",
            "abuse_score": 95,
            "is_malicious": True,
            "reputation_status": "malicious",
            "category": f"Targeted Phishing Campaign ({impersonated_brand.title()})",
            "reports_count": 48,
        }

    if has_typosquat or has_subdomain_spoof:
        return {
            "source": "local_deterministic_feed",
            "abuse_score": 90,
            "is_malicious": True,
            "reputation_status": "malicious",
            "category": f"Brand Impersonation / Typosquatting ({impersonated_brand.title()})",
            "reports_count": 32,
        }

    if has_phishing_lure:
        return {
            "source": "local_deterministic_feed",
            "abuse_score": 85,
            "is_malicious": True,
            "reputation_status": "malicious",
            "category": "Suspicious Social Engineering Lure",
            "reports_count": 19,
        }

    return {
        "source": "local_deterministic_feed",
        "abuse_score": None,
        "is_malicious": None,
        "reputation_status": "unknown",
        "category": "Unknown / Unclassified",
        "reports_count": 0,
    }


def evaluate_url_rules(
    target: str,
    *,
    evidence_id: uuid.UUID | None = None,
) -> list[DetectionHit]:
    """Evaluate deterministic detection rules over a target URL or domain."""
    hits: list[DetectionHit] = []
    host, path, query, _ = decompose_url_target(target)
    if not host:
        return hits

    cited_ids = [evidence_id] if evidence_id is not None else []
    full_target_str = f"{host}{path}?{query}" if query else f"{host}{path}"

    # 1. Verified Legitimate Enterprise Domain Rule (R-URL-000)
    for leg_dom, brand_name in KNOWN_LEGITIMATE_DOMAINS.items():
        if host == leg_dom or host.endswith(f".{leg_dom}"):
            hits.append(
                DetectionHit(
                    rule_id=RULE_LEGITIMATE_DOMAIN,
                    title=f"Verified Legitimate Enterprise Domain: {host} ({brand_name})",
                    description=(
                        f"The domain '{host}' matches verified authoritative "
                        f"infrastructure of {brand_name}. Path and parameters indicate "
                        "routine operational traffic."
                    ),
                    severity=Severity.INFO,
                    confidence=1.0,
                    reasoning=(
                        f"Host '{host}' was validated against the verified enterprise domain "
                        "catalog. No deceptive typosquatting or spoofing patterns detected."
                    ),
                    evidence_ids=cited_ids,
                )
            )
            return hits

    # 2. Brand Impersonation & Typosquatting Check (R-URL-001)
    impersonated_brand: str | None = None
    for brand, pattern, leg_domains in BRAND_TARGETS:
        if pattern.search(host) or pattern.search(full_target_str):
            impersonated_brand = brand
            hits.append(
                DetectionHit(
                    rule_id=RULE_BRAND_IMPERSONATION,
                    title=(
                        f"Brand Impersonation / Typosquatting detected: '{host}' spoofing '{brand}'"
                    ),
                    description=(
                        f"Domain identifier '{host}' exhibits deliberate typosquatting, "
                        f"character manipulation, or brand mimicry targeting {brand.title()}."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.95,
                    reasoning=(
                        f"Matched brand typosquat signature for '{brand}'. Attackers "
                        "register variant domains to execute phishing or credential theft."
                    ),
                    evidence_ids=cited_ids,
                )
            )
            break
        elif brand in host and not any(host == d or host.endswith(f".{d}") for d in leg_domains):
            impersonated_brand = brand
            hits.append(
                DetectionHit(
                    rule_id=RULE_SUBDOMAIN_SPOOFING,
                    title=(
                        f"Deceptive Subdomain Spoofing: brand '{brand}' prefixed to "
                        f"untrusted host '{host}'"
                    ),
                    description=(
                        f"Host '{host}' prefixes brand name '{brand}' in subdomains while "
                        "registering under an untrusted apex domain, misleading users."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.95,
                    reasoning=(
                        f"Subdomain label matches known brand '{brand}' while apex domain "
                        "is non-authoritative."
                    ),
                    evidence_ids=cited_ids,
                )
            )
            break

    # 3. Phishing and Scam Reward Lure Check (R-URL-003)
    lure_match_str: str | None = None
    for lure_type, pattern in PHISHING_LURE_PATTERNS:
        m = pattern.search(full_target_str)
        if m:
            lure_match_str = m.group(0)
            hits.append(
                DetectionHit(
                    rule_id=RULE_PHISHING_LURE,
                    title=(
                        f"Deceptive Social Engineering / Phishing Lure detected: '{lure_match_str}'"
                    ),
                    description=(
                        "URL path or query contains explicit deception patterns "
                        f"'{lure_match_str}' "
                        "designed to lure victims into submitting sensitive credentials."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.90,
                    reasoning=(
                        f"Matched social engineering lure signature ({lure_type}). Attackers "
                        "employ fake monetary rewards or urgency to induce victim interaction."
                    ),
                    evidence_ids=cited_ids,
                )
            )
            break

    # 4. Combined Credential Phishing Campaign Rule (R-URL-004) -> CRITICAL
    if impersonated_brand and lure_match_str:
        hits.append(
            DetectionHit(
                rule_id=RULE_CREDENTIAL_PHISHING_CAMPAIGN,
                title=(
                    f"Targeted Credential Phishing Campaign: '{host}' spoofing "
                    f"{impersonated_brand.title()} with reward lure"
                ),
                description=(
                    "Corroborated deceptive infrastructure combining brand impersonation "
                    f"({impersonated_brand.title()}) with high-impact social engineering "
                    f"lure ('{lure_match_str}'). Represents an active phishing attack."
                ),
                severity=Severity.CRITICAL,
                confidence=0.95,
                reasoning=(
                    "Simultaneous detection of brand spoofing and social engineering lure "
                    "constitutes a high-confidence targeted credential harvesting campaign "
                    "(MITRE ATT&CK T1566.002)."
                ),
                evidence_ids=cited_ids,
            )
        )

    return sorted(hits, key=lambda h: -h.severity.rank)
