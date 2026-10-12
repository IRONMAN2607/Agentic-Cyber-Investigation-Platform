"""Triage agent.

Extracts investigation entities, classifies the submission, inventories initial
indicators via deterministic tools, identifies evidence gaps, and produces an
initial investigation plan using structured model reasoning (or rule-based fallback).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from acip.agents.base import Agent, AgentContext, AgentResult
from acip.agents.triage_schemas import (
    EvidenceGap,
    ExtractedEntity,
    IndicatorAssessment,
    InputClassification,
    PlannedTaskProposal,
    TriageAnalysis,
)
from acip.core.evidence.contracts import FindingDraft
from acip.core.llm.contracts import ChatMessage, MessageRole
from acip.db.models import Evidence
from acip.logging import get_logger
from acip.tools.ioc_extractor import IOCExtractor
from acip.types import (
    AgentCapability,
    ArtifactKind,
    AssertionClass,
    EvidenceKind,
    RunStatus,
    Severity,
    TargetType,
    TaskClass,
)

logger = get_logger(__name__)

# Target types whose value is itself an indicator worth scanning.
_SCANNABLE_TARGETS = frozenset(
    {
        TargetType.URL,
        TargetType.IP,
        TargetType.DOMAIN,
        TargetType.HASH,
        TargetType.DESCRIPTION,
        TargetType.LOG,
        TargetType.FILE,
        TargetType.PCAP,
    }
)
_MAX_CITED = 10
_MAX_SNIPPET_BYTES = 4096


class TriageAgent(Agent):
    """Classifies the submission, extracts entities, assesses indicators, and plans next steps."""

    name: ClassVar[str] = "triage"
    version: ClassVar[str] = "2.0.0"
    capability: ClassVar[AgentCapability] = AgentCapability.TRIAGE
    description: ClassVar[str] = (
        "Extracts entities, classifies the submission, inventories indicators, "
        "identifies evidence gaps, and formulates an initial investigation plan."
    )

    async def run(self, ctx: AgentContext, inputs: dict[str, Any]) -> AgentResult:
        collected: list[Evidence] = []
        warnings: list[str] = []
        metrics: dict[str, Any] = {"sources_scanned": 0}

        ioc_evidence: list[Evidence] = []

        # 1. Deterministic Extraction via IOCExtractor
        if ctx.investigation.target_type_enum in _SCANNABLE_TARGETS:
            invocation = await ctx.tools.run(
                IOCExtractor.name,
                {"text": ctx.investigation.target_value},
                agent_run_id=ctx.agent_run_id,
            )
            collected.extend(invocation.evidence)
            ioc_evidence.extend(invocation.evidence)
            warnings.extend(invocation.result.warnings)
            metrics["sources_scanned"] += 1

        for artifact in ctx.artifacts:
            invocation = await ctx.tools.run(
                IOCExtractor.name,
                {},
                agent_run_id=ctx.agent_run_id,
                artifact_id=artifact.id,
                artifact_path=_path(artifact),
            )
            collected.extend(invocation.evidence)
            ioc_evidence.extend(invocation.evidence)
            warnings.extend(invocation.result.warnings)
            metrics["sources_scanned"] += 1

        # 1b. Deterministic Packet Capture Parsing via PcapParser
        pcap_artifacts = [
            a
            for a in ctx.artifacts
            if a.kind in {ArtifactKind.PCAP.value, ArtifactKind.PCAP_NG.value}
            or a.original_filename.lower().endswith((".pcap", ".pcapng"))
        ]
        pcap_evidence_list: list[Evidence] = []
        for pcap_art in pcap_artifacts:
            try:
                pcap_inv = await ctx.tools.run(
                    "pcap_parser",
                    {},
                    agent_run_id=ctx.agent_run_id,
                    artifact_id=pcap_art.id,
                    artifact_path=_path(pcap_art),
                )
                collected.extend(pcap_inv.evidence)
                pcap_evidence_list.extend(pcap_inv.evidence)
                warnings.extend(pcap_inv.result.warnings)
                metrics["sources_scanned"] += 1
            except Exception as exc:
                logger.warning(
                    "pcap parsing failed for artifact %s: %s",
                    pcap_art.original_filename,
                    exc,
                )

        # 1c. Threat Intelligence Enrichment via ThreatIntelTool
        ti_candidates: list[tuple[str, str]] = []  # (indicator_value, indicator_type)
        t_val = ctx.investigation.target_value.strip()

        # Check direct investigation target
        if ctx.investigation.target_type_enum == TargetType.IP and t_val:
            ti_candidates.append((t_val, "ip"))
        elif ctx.investigation.target_type_enum == TargetType.DOMAIN and t_val:
            ti_candidates.append((t_val, "domain"))
        elif ctx.investigation.target_type_enum == TargetType.HASH and t_val:
            ti_candidates.append((t_val, "hash"))
        elif ctx.investigation.target_type_enum == TargetType.URL and t_val:
            parsed_host = _extract_host_from_url(t_val)
            if parsed_host:
                h_type = "ip" if _is_ip_address(parsed_host) else "domain"
                ti_candidates.append((parsed_host, h_type))

        # Check extracted IOCs and DNS queries
        for row in collected:
            i_type = str(row.data.get("ioc_type", ""))
            i_val = str(row.data.get("value") or row.data.get("match") or "").strip()
            if not i_val:
                continue
            if i_type in {"ipv4", "ipv6"} and row.data.get("scope", "global") == "global":
                ti_candidates.append((i_val, "ip"))
            elif i_type == "domain":
                ti_candidates.append((i_val, "domain"))
            elif i_type in {"sha256", "sha1", "md5"}:
                ti_candidates.append((i_val, "hash"))
            elif i_type == "url":
                parsed_host = _extract_host_from_url(i_val)
                if parsed_host:
                    h_type = "ip" if _is_ip_address(parsed_host) else "domain"
                    ti_candidates.append((parsed_host, h_type))
            elif row.kind == EvidenceKind.DNS_QUERY.value:
                q_val = str(row.data.get("query", "")).strip()
                if q_val:
                    ti_candidates.append((q_val, "domain"))

        # Deduplicate candidates preserving order
        deduped_ti: list[tuple[str, str]] = []
        seen_ti: set[tuple[str, str]] = set()
        for cand in ti_candidates:
            if cand not in seen_ti and cand[0]:
                seen_ti.add(cand)
                deduped_ti.append(cand)

        threat_intel_evidence: list[Evidence] = []
        for ind_val, ind_type in deduped_ti[:15]:
            try:
                ti_inv = await ctx.tools.run(
                    "threat_intel",
                    {
                        "indicator": ind_val,
                        "indicator_type": ind_type,
                        "opt_in_external_lookup": True,
                    },
                    agent_run_id=ctx.agent_run_id,
                )
                collected.extend(ti_inv.evidence)
                threat_intel_evidence.extend(ti_inv.evidence)
                warnings.extend(ti_inv.result.warnings)
            except Exception as exc:
                logger.warning(
                    "threat intelligence lookup failed for %s: %s",
                    ind_val,
                    exc,
                )

        by_type: dict[str, int] = {}
        global_indicators: list[Evidence] = []
        for row in collected:
            ioc_type = str(row.data.get("ioc_type") or row.data.get("indicator_type") or row.kind)
            by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
            if row.data.get("scope", "global") == "global":
                global_indicators.append(row)

        metrics["indicators_total"] = len(ioc_evidence)
        metrics["evidence_total"] = len(collected)
        metrics["indicators_by_type"] = by_type
        metrics["externally_routable"] = len(global_indicators)
        metrics["threat_intel_lookups"] = len(threat_intel_evidence)
        metrics["pcap_evidence_count"] = len(pcap_evidence_list)

        # 2. Structured Triage Reasoning (via ModelRouter or Rule-Based Fallback)
        analysis = await self._perform_triage_analysis(ctx, collected, global_indicators, by_type)

        metrics["entities_extracted"] = len(analysis.entities)
        metrics["classification_category"] = analysis.classification.category
        metrics["classification_confidence"] = analysis.classification.confidence
        metrics["evidence_gaps_count"] = len(analysis.evidence_gaps)
        metrics["planned_tasks_count"] = len(analysis.investigation_plan)

        # 3. Record Grounded Findings
        findings = await self._record_findings(
            ctx,
            collected,
            global_indicators,
            by_type,
            analysis,
            threat_intel_evidence=threat_intel_evidence,
            pcap_evidence=pcap_evidence_list,
        )

        next_actions = [
            f"[{proposal.priority}] {proposal.task_type}: {proposal.rationale}"
            for proposal in sorted(analysis.investigation_plan, key=lambda p: p.priority)
        ]
        if not next_actions and global_indicators:
            next_actions = ["Enrich externally-routable indicators with threat intelligence"]

        metrics["triage_analysis"] = analysis.model_dump(mode="json")

        summary = (
            f"Triage classified input as '{analysis.classification.category}' "
            f"({len(collected)} indicator(s), {len(analysis.entities)} entity(ies)). "
            f"{analysis.classification.summary}"
        )

        return AgentResult(
            status=RunStatus.SUCCEEDED,
            summary=summary,
            evidence_ids=[str(row.id) for row in collected],
            finding_ids=findings,
            metrics=metrics,
            next_actions=next_actions,
            errors=[],
        )

    async def _perform_triage_analysis(
        self,
        ctx: AgentContext,
        collected: list[Evidence],
        global_indicators: list[Evidence],
        by_type: dict[str, int],
    ) -> TriageAnalysis:
        """Perform structured model-driven triage analysis with fallback to heuristics."""
        if ctx.settings.enable_llm_triage and ctx.router is not None:
            try:
                messages = self._build_prompt_messages(ctx, collected)
                analysis, _resp = await ctx.router.complete(
                    task_class=TaskClass.CLASSIFICATION,
                    messages=messages,
                    schema=TriageAnalysis,
                    investigation_id=ctx.investigation.id,
                    agent_run_id=ctx.agent_run_id,
                    prompt_name="triage_analysis",
                    prompt_version="2.0.0",
                    session=ctx.session,
                )
                if analysis is not None:
                    logger.info(
                        "model-based triage analysis succeeded",
                        extra={
                            "category": analysis.classification.category,
                            "entities_count": len(analysis.entities),
                            "confidence": analysis.classification.confidence,
                        },
                    )
                    return analysis
            except Exception as exc:
                logger.warning(
                    "model-based triage failed, falling back to deterministic heuristics",
                    extra={"error_type": type(exc).__name__, "error_msg": str(exc)},
                )

        return self._deterministic_fallback_analysis(ctx, collected, global_indicators, by_type)

    def _build_prompt_messages(
        self, ctx: AgentContext, collected: list[Evidence]
    ) -> list[ChatMessage]:
        system_prompt = (
            "You are an expert cybersecurity triage agent in AACIP.\n"
            "Your mission is to perform initial triage over submitted investigation targets.\n"
            "Provide structured analysis strictly adhering to the schema with:\n"
            "1. Entities: Extract relevant entities with identified roles and context.\n"
            "2. Classification: Categorize the incident/submission, severity, and reasoning.\n"
            "3. Indicators: Evaluate extracted indicators, their scope and threat assessment.\n"
            "4. Evidence Gaps: Identify missing context or uncollected data sources.\n"
            "5. Investigation Plan: Propose prioritized next tasks with clear rationale.\n\n"
            "Ground your analysis strictly in the provided artifacts and indicators."
        )

        artifact_details: list[str] = []
        for art in ctx.artifacts:
            snippet = _read_artifact_snippet(art)
            preview_text = f"\n  Excerpt: {snippet[:500]}..." if snippet else ""
            artifact_details.append(
                f"- File: {art.original_filename} (Kind: {art.kind}, "
                f"Size: {art.size_bytes}B){preview_text}"
            )
        artifact_block = (
            "\n".join(artifact_details) if artifact_details else "No artifacts attached."
        )

        ioc_details: list[str] = []
        for row in collected[:25]:
            val = row.data.get("value") or row.data.get("match") or ""
            ioc_type = row.data.get("ioc_type", "unknown")
            scope = row.data.get("scope", "global")
            ioc_details.append(f"- {ioc_type}: {val} (scope: {scope})")
        ioc_block = "\n".join(ioc_details) if ioc_details else "No indicators extracted."

        user_prompt = (
            f"Investigation Title: {ctx.investigation.title}\n"
            f"Target Type: {ctx.investigation.target_type}\n"
            f"Target Value: {ctx.investigation.target_value}\n\n"
            f"Attached Artifacts:\n{artifact_block}\n\n"
            f"Extracted Indicators ({len(collected)} total):\n{ioc_block}\n\n"
            "Analyze this submission and generate the complete structured triage analysis."
        )

        return [
            ChatMessage(role=MessageRole.SYSTEM, content=system_prompt),
            ChatMessage(role=MessageRole.USER, content=user_prompt),
        ]

    def _deterministic_fallback_analysis(
        self,
        ctx: AgentContext,
        collected: list[Evidence],
        global_indicators: list[Evidence],
        by_type: dict[str, int],
    ) -> TriageAnalysis:
        """Deterministic rule-based triage used when model router is unavailable."""
        has_auth_log = any(a.kind in {"linux_auth_log", "syslog"} for a in ctx.artifacts)
        is_auth_target = ctx.investigation.target_type_enum == TargetType.LOG

        if has_auth_log or is_auth_target:
            category = "authentication_attack"
            summary = "Authentication log submission containing login and session events."
            severity = Severity.INFO
            reasoning = (
                "Authentication logs submitted for analysis; requires log_analysis agent "
                "to evaluate deterministic brute-force and privilege rules."
            )
        elif ctx.investigation.target_type_enum in {TargetType.URL, TargetType.DOMAIN}:
            category = "suspicious_infrastructure"
            summary = (
                f"Target {ctx.investigation.target_type} ({ctx.investigation.target_value}) "
                "submitted for infrastructure analysis."
            )
            severity = Severity.INFO
            reasoning = (
                "Network identifier provided without local logs; requires reputation lookup."
            )
        elif ctx.investigation.target_type_enum in {TargetType.HASH, TargetType.FILE}:
            category = "malware_suspect"
            summary = (
                f"File/hash target ({ctx.investigation.target_value}) submitted for inspection."
            )
            severity = Severity.INFO
            reasoning = "File or hash indicator submitted; requires static/dynamic analysis."
        else:
            category = "incident_triage"
            summary = f"Initial triage for investigation '{ctx.investigation.title}'."
            severity = Severity.INFO
            reasoning = "Baseline extraction completed; awaiting further evidence."

        classification = InputClassification(
            category=category,
            summary=summary,
            confidence=0.85,
            initial_severity=severity,
            reasoning=reasoning,
        )

        entities: list[ExtractedEntity] = []
        indicators: list[IndicatorAssessment] = []
        seen_entities: set[tuple[str, str]] = set()

        for row in collected:
            val = str(row.data.get("value") or "")
            ioc_type = str(row.data.get("ioc_type") or "unknown")
            scope = str(row.data.get("scope") or "global")
            if val and (ioc_type, val) not in seen_entities:
                seen_entities.add((ioc_type, val))
                role = "attacker" if scope == "global" else "target_or_internal"
                entities.append(
                    ExtractedEntity(
                        entity_type=ioc_type,
                        value=val,
                        role=role,
                        context=f"Extracted from {row.source_tool}",
                    )
                )
                indicators.append(
                    IndicatorAssessment(
                        indicator_type=ioc_type,
                        value=val,
                        scope=scope,
                        threat_assessment=(
                            "unverified_external" if scope == "global" else "internal_asset"
                        ),
                        is_malicious_candidate=scope == "global",
                    )
                )

        gaps: list[EvidenceGap] = []
        if global_indicators:
            gaps.append(
                EvidenceGap(
                    description=(
                        f"Reputation of {len(global_indicators)} external indicator(s) unverified"
                    ),
                    required_source="threat_intelligence_enrichment",
                    importance="high",
                )
            )
        if has_auth_log:
            gaps.append(
                EvidenceGap(
                    description="Network packet captures (PCAP) not attached",
                    required_source="network_pcap",
                    importance="medium",
                )
            )

        plan: list[PlannedTaskProposal] = []
        prio = 1
        if has_auth_log:
            plan.append(
                PlannedTaskProposal(
                    task_type="log_analysis",
                    rationale=(
                        "Parse auth logs and evaluate deterministic rules for credential abuse"
                    ),
                    priority=prio,
                )
            )
            prio += 1
            plan.append(
                PlannedTaskProposal(
                    task_type="mitre",
                    rationale="Map observed detection rules to verified MITRE ATT&CK techniques",
                    priority=prio,
                )
            )
            prio += 1

        plan.append(
            PlannedTaskProposal(
                task_type="correlation",
                rationale=(
                    "Correlate evidence into canonical entity graph and resolve cross-source edges"
                ),
                priority=prio,
            )
        )
        prio += 1

        plan.append(
            PlannedTaskProposal(
                task_type="reasoning",
                rationale="Perform multi-hop graph path analysis to reconstruct attack progression",
                priority=prio,
            )
        )
        prio += 1

        plan.append(
            PlannedTaskProposal(
                task_type="hypothesis",
                rationale=(
                    "Formulate competing candidate explanations declaring refutation criteria"
                ),
                priority=prio,
            )
        )
        prio += 1

        plan.append(
            PlannedTaskProposal(
                task_type="validation",
                rationale=(
                    "Evaluate refutation conditions against observed evidence to resolve hypotheses"
                ),
                priority=prio,
            )
        )
        prio += 1

        plan.append(
            PlannedTaskProposal(
                task_type="reporting",
                rationale="Synthesize all evidence, findings, and gaps into an executive report",
                priority=prio,
            )
        )

        return TriageAnalysis(
            classification=classification,
            entities=entities,
            indicators=indicators,
            evidence_gaps=gaps,
            investigation_plan=plan,
        )

    async def _record_findings(
        self,
        ctx: AgentContext,
        collected: list[Evidence],
        global_indicators: list[Evidence],
        by_type: dict[str, int],
        analysis: TriageAnalysis,
        threat_intel_evidence: list[Evidence] | None = None,
        pcap_evidence: list[Evidence] | None = None,
    ) -> list[str]:
        findings: list[str] = []

        # 1. Deterministic Indicator Inventory FACT (G1 compliant)
        if collected:
            breakdown = ", ".join(f"{count} {name}" for name, count in sorted(by_type.items()))
            finding = await ctx.store.add_finding(
                FindingDraft(
                    title=f"{len(collected)} indicator(s) extracted from submitted evidence",
                    description=(
                        f"Deterministic extraction over {len(collected)} distinct indicator(s) "
                        f"({breakdown}). Values were validated after matching: addresses were "
                        "parsed, hashes length-checked, and domain candidates filtered against "
                        "a file-extension denylist."
                    ),
                    assertion_class=AssertionClass.FACT,
                    severity=Severity.INFO,
                    confidence=1.0,
                    evidence_ids=[row.id for row in collected[:_MAX_CITED]],
                    detection_rule="triage.ioc_inventory",
                ),
                agent_run_id=ctx.agent_run_id,
            )
            findings.append(str(finding.id))
        else:
            finding = await ctx.store.add_finding(
                FindingDraft(
                    title="No indicators could be extracted from the submitted evidence",
                    description=(
                        "Extraction ran successfully but matched no addresses, domains, URLs, "
                        "hashes or email addresses. The submission may contain no indicators, "
                        "or may be in a format this deployment cannot yet parse."
                    ),
                    assertion_class=AssertionClass.UNKNOWN,
                    severity=Severity.INFO,
                    confidence=1.0,
                    reasoning=(
                        "Absence of a match is not evidence of absence of indicators; it "
                        "bounds only what the current extractor covers."
                    ),
                ),
                agent_run_id=ctx.agent_run_id,
            )
            findings.append(str(finding.id))

        # 2. Threat Intelligence Reputation Findings (FACT, G1 compliant)
        for ti_ev in threat_intel_evidence or []:
            data = ti_ev.data or {}
            indicator = str(data.get("indicator") or "unknown")
            is_mal = bool(data.get("is_malicious", False))
            source = str(data.get("source", "ThreatIntel"))
            score = int(data.get("abuse_score", 0))
            category = str(data.get("category", "Threat Intelligence"))
            reports = int(data.get("reports_count", 0))

            if is_mal:
                finding_ti = await ctx.store.add_finding(
                    FindingDraft(
                        title=f"Threat Intelligence Alert: {indicator} ({category})",
                        description=(
                            f"Indicator '{indicator}' is flagged as malicious by {source} "
                            f"with an abuse score of {score}% ({reports} report(s)). "
                            f"Threat Category: {category}."
                        ),
                        assertion_class=AssertionClass.FACT,
                        severity=Severity.CRITICAL if score >= 95 else Severity.HIGH,
                        confidence=min(1.0, max(0.8, score / 100.0)),
                        evidence_ids=[ti_ev.id],
                        detection_rule="threat_intel.reputation",
                    ),
                    agent_run_id=ctx.agent_run_id,
                )
                findings.append(str(finding_ti.id))
            elif indicator == ctx.investigation.target_value.strip():
                finding_ti = await ctx.store.add_finding(
                    FindingDraft(
                        title=f"Threat Intelligence: {indicator} (Clean / Low Risk)",
                        description=(
                            f"Indicator '{indicator}' was checked against {source}. "
                            f"Abuse score is {score}%. No malicious activity was reported."
                        ),
                        assertion_class=AssertionClass.FACT,
                        severity=Severity.INFO,
                        confidence=1.0,
                        evidence_ids=[ti_ev.id],
                        detection_rule="threat_intel.reputation",
                    ),
                    agent_run_id=ctx.agent_run_id,
                )
                findings.append(str(finding_ti.id))

        # 3. PCAP Network Traffic Findings (FACT, G1 compliant)
        if pcap_evidence:
            flow_count = sum(1 for e in pcap_evidence if e.kind == EvidenceKind.NETWORK_FLOW.value)
            dns_count = sum(1 for e in pcap_evidence if e.kind == EvidenceKind.DNS_QUERY.value)
            if flow_count > 0 or dns_count > 0:
                pcap_finding = await ctx.store.add_finding(
                    FindingDraft(
                        title=(
                            f"Network Packet Capture: {flow_count} flow(s), "
                            f"{dns_count} DNS query(ies)"
                        ),
                        description=(
                            f"Deterministic packet dissection extracted {flow_count} network "
                            f"flow(s) and {dns_count} DNS query resolution(s) from attached "
                            "packet capture artifacts."
                        ),
                        assertion_class=AssertionClass.FACT,
                        severity=Severity.INFO,
                        confidence=1.0,
                        evidence_ids=[e.id for e in pcap_evidence[:_MAX_CITED]],
                        detection_rule="pcap.traffic_inventory",
                    ),
                    agent_run_id=ctx.agent_run_id,
                )
                findings.append(str(pcap_finding.id))

        # 4. Triage Classification (INFERENCE or HYPOTHESIS) (G2/G3 compliant)
        formatted_cat = analysis.classification.category.replace("_", " ").title()
        if collected:
            finding_cls = await ctx.store.add_finding(
                FindingDraft(
                    title=f"Triage Assessment: {formatted_cat}",
                    description=analysis.classification.summary,
                    assertion_class=AssertionClass.INFERENCE,
                    severity=Severity.INFO,
                    confidence=analysis.classification.confidence,
                    evidence_ids=[row.id for row in collected[:_MAX_CITED]],
                    reasoning=analysis.classification.reasoning,
                    detection_rule="triage.classification",
                ),
                agent_run_id=ctx.agent_run_id,
            )
            findings.append(str(finding_cls.id))
        else:
            finding_cls = await ctx.store.add_finding(
                FindingDraft(
                    title=f"Triage Hypothesis: {formatted_cat}",
                    description=analysis.classification.summary,
                    assertion_class=AssertionClass.HYPOTHESIS,
                    severity=Severity.INFO,
                    confidence=analysis.classification.confidence,
                    reasoning=analysis.classification.reasoning,
                    detection_rule="triage.classification",
                ),
                agent_run_id=ctx.agent_run_id,
            )
            findings.append(str(finding_cls.id))

        # 5. Evidence Gaps (UNKNOWN, bounded to <= INFO per G4)
        for gap in analysis.evidence_gaps:
            finding_gap = await ctx.store.add_finding(
                FindingDraft(
                    title=f"Evidence Gap: {gap.description}",
                    description=(
                        f"Unresolved investigation gap. Required data source: "
                        f"{gap.required_source} (Importance: {gap.importance})."
                    ),
                    assertion_class=AssertionClass.UNKNOWN,
                    severity=Severity.INFO,
                    confidence=1.0,
                    evidence_ids=[row.id for row in global_indicators[:_MAX_CITED]],
                    reasoning=(
                        f"Identified during initial triage. Resolving this gap "
                        f"requires {gap.required_source}."
                    ),
                ),
                agent_run_id=ctx.agent_run_id,
            )
            findings.append(str(finding_gap.id))

        return findings


def _path(artifact: Any) -> Path:
    return Path(artifact.storage_path)


def _extract_host_from_url(url: str) -> str:
    """Safely extract the domain or IP hostname from a URL candidate."""
    from urllib.parse import urlparse

    clean_url = url.strip()
    if not clean_url.startswith(("http://", "https://", "ftp://")):
        clean_url = f"http://{clean_url}"
    try:
        parsed = urlparse(clean_url)
        return parsed.hostname or ""
    except Exception:
        return ""


def _is_ip_address(candidate: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    import ipaddress

    try:
        ipaddress.ip_address(candidate.strip())
        return True
    except ValueError:
        return False


def _read_artifact_snippet(artifact: Any, max_bytes: int = _MAX_SNIPPET_BYTES) -> str:
    try:
        path = _path(artifact)
        if path.is_file():
            raw = path.read_bytes()[:max_bytes]
            return raw.decode("utf-8", errors="replace")
    except OSError as exc:
        logger.debug("could not read artifact snippet", extra={"error": str(exc)})
    return ""


__all__ = ["TriageAgent"]
