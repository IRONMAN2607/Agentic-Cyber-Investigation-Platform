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
from acip.core.detection.url_rules import (
    RULE_LEGITIMATE_DOMAIN,
    decompose_url_target,
    evaluate_url_rules,
)
from acip.core.detection.url_rules import (
    DetectionHit as UrlDetectionHit,
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
_MAX_SNIPPET_BYTES = 16384


class TriageAgent(Agent):
    """Classifies the submission, extracts entities, assesses indicators, and plans next steps."""

    name: ClassVar[str] = "triage"
    version: ClassVar[str] = "2.1.0"
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
            ti_candidates.append((t_val, "url"))

        # Check extracted IOCs and DNS queries
        for row in collected:
            i_type = str(
                row.data.get("ioc_type")
                or row.data.get("type")
                or row.data.get("indicator_type")
                or ""
            )
            i_val = str(row.data.get("value") or row.data.get("match") or "").strip()
            if not i_val:
                i_val = str(row.data.get("query_domain") or row.data.get("query") or "").strip()
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
                ti_candidates.append((i_val, "url"))
            elif row.kind == EvidenceKind.DNS_QUERY.value:
                q_val = str(row.data.get("query_domain") or row.data.get("query") or "").strip()
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

        # 1d. Deterministic URL and Domain Rule Evaluation
        url_detection_hits: list[UrlDetectionHit] = []
        target_val_clean = ctx.investigation.target_value.strip()
        is_url_or_domain = (
            ctx.investigation.target_type_enum in {TargetType.URL, TargetType.DOMAIN}
            or "/" in target_val_clean
            or any(target_val_clean.endswith(ext) for ext in {".com", ".org", ".net", ".io", ".ai"})
        )
        if is_url_or_domain and target_val_clean:
            matching_ev = next(
                (e for e in threat_intel_evidence if e.data.get("indicator") == target_val_clean),
                None,
            )
            ev_id = matching_ev.id if matching_ev else (collected[0].id if collected else None)
            url_detection_hits = evaluate_url_rules(target_val_clean, evidence_id=ev_id)

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
        metrics["url_rules_fired"] = len(url_detection_hits)

        # 2. Structured Triage Reasoning (via ModelRouter or Rule-Based Fallback)
        analysis, is_model_driven = await self._perform_triage_analysis(
            ctx,
            collected,
            global_indicators,
            by_type,
            threat_intel_evidence=threat_intel_evidence,
            url_detection_hits=url_detection_hits,
        )

        metrics["entities_extracted"] = len(analysis.entities)
        metrics["classification_category"] = analysis.classification.category
        metrics["classification_confidence"] = analysis.classification.confidence
        metrics["evidence_gaps_count"] = len(analysis.evidence_gaps)
        metrics["planned_tasks_count"] = len(analysis.investigation_plan)
        metrics["is_model_driven"] = is_model_driven

        # 3. Record Grounded Findings
        findings = await self._record_findings(
            ctx,
            collected,
            global_indicators,
            by_type,
            analysis,
            threat_intel_evidence=threat_intel_evidence,
            pcap_evidence=pcap_evidence_list,
            url_detection_hits=url_detection_hits,
            is_model_driven=is_model_driven,
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
        threat_intel_evidence: list[Evidence] | None = None,
        url_detection_hits: list[UrlDetectionHit] | None = None,
    ) -> tuple[TriageAnalysis, bool]:
        """Perform structured model-driven triage analysis with fallback to heuristics."""
        if ctx.settings.enable_llm_triage and ctx.router is not None:
            try:
                messages = self._build_prompt_messages(
                    ctx,
                    collected,
                    threat_intel_evidence=threat_intel_evidence,
                    url_detection_hits=url_detection_hits,
                )
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
                    return analysis, True
            except Exception as exc:
                logger.warning(
                    "model-based triage failed, falling back to deterministic heuristics",
                    extra={"error_type": type(exc).__name__, "error_msg": str(exc)},
                )

        return (
            self._deterministic_fallback_analysis(
                ctx,
                collected,
                global_indicators,
                by_type,
                url_detection_hits=url_detection_hits,
            ),
            False,
        )

    def _build_prompt_messages(
        self,
        ctx: AgentContext,
        collected: list[Evidence],
        threat_intel_evidence: list[Evidence] | None = None,
        url_detection_hits: list[UrlDetectionHit] | None = None,
    ) -> list[ChatMessage]:
        system_prompt = (
            "You are an expert cybersecurity triage agent in AACIP with access to current (2026) "
            "threat intelligence.\n"
            "Your mission is to perform initial triage over submitted investigation targets.\n"
            "Provide structured analysis strictly adhering to the schema with:\n"
            "1. Entities: Extract relevant entities with identified roles and context.\n"
            "2. Classification: Categorize the incident/submission, severity, and reasoning.\n"
            "3. Indicators: Evaluate extracted indicators, their scope and threat assessment.\n"
            "4. Evidence Gaps: Identify missing context or uncollected data sources.\n"
            "5. Investigation Plan: Propose prioritized next tasks with clear rationale.\n\n"
            "Ground your analysis strictly in the provided artifacts and indicators.\n\n"
            "Current Threat Intelligence Guidance (2026):\n"
            "- Brand Impersonation & Typosquatting: Attackers frequently register subtle "
            "variations of high-profile brands (e.g., 'microslop' for Microsoft, deceptive "
            "variants of Google, "
            "Anthropic/Claude, Apple, PayPal). Such domains are malicious by intent when coupled "
            "with social engineering.\n"
            "- Phishing & Deceptive Lures: Paths and queries containing fake financial incentives, "
            "reward claims, urgent account verifications (e.g., 'rewards/claim5000discount', "
            "'crypto-airdrop', 'verify-account') represent high/critical risk credential "
            "harvesting or malware delivery (MITRE ATT&CK T1566.002).\n"
            "- Authoritative Enterprise Infrastructure: Legitimate authoritative domains (e.g., "
            "'claude.com', 'anthropic.com', 'microsoft.com', 'google.com') serving routine "
            "business endpoints (such as '/contact-sales/education-plan') are verified benign "
            "infrastructure. Categorized with severity INFO and confidence >= 0.95.\n"
            "- Never classify verified authoritative enterprise domains as malicious based "
            "merely on external routing."
        )

        artifact_details: list[str] = []
        for art in ctx.artifacts:
            snippet = _read_artifact_snippet(art)
            preview_text = f"\n  Excerpt:\n{snippet[:_MAX_SNIPPET_BYTES]}" if snippet else ""
            artifact_details.append(
                f"- File: {art.original_filename} (Kind: {art.kind}, "
                f"Size: {art.size_bytes}B){preview_text}"
            )
        artifact_block = (
            "\n".join(artifact_details) if artifact_details else "No artifacts attached."
        )

        ioc_details: list[str] = []
        for row in collected[:25]:
            val = row.data.get("value") or row.data.get("match") or row.data.get("indicator") or ""
            ioc_type = row.data.get("ioc_type") or row.data.get("indicator_type") or row.kind
            scope = row.data.get("scope", "global")
            if val:
                ioc_details.append(f"- {ioc_type}: {val} (scope: {scope})")
        ioc_block = "\n".join(ioc_details) if ioc_details else "No indicators extracted."

        target_breakdown = ""
        t_val = ctx.investigation.target_value.strip()
        is_target_url = (
            ctx.investigation.target_type_enum in {TargetType.URL, TargetType.DOMAIN}
            or "/" in t_val
        )
        if is_target_url:
            host, path, query, clean_url = decompose_url_target(t_val)
            target_breakdown = (
                f"\nURL Target Decomposition:\n"
                f"- Host / Domain: {host}\n"
                f"- Path: {path}\n"
                f"- Query Parameters: {query or 'None'}\n"
                f"- Normalized URL: {clean_url}\n"
            )

        ti_block_items: list[str] = []
        for ti in threat_intel_evidence or []:
            d = ti.data or {}
            ind = d.get("indicator")
            if ind:
                ti_block_items.append(
                    f"- {ind} ({d.get('indicator_type', 'ioc')}): "
                    f"Reputation={d.get('reputation_status')} | "
                    f"Abuse Score={d.get('abuse_score')}% | "
                    f"Category={d.get('category')} | Source={d.get('source')}"
                )
        ti_block = (
            "\n".join(ti_block_items) if ti_block_items else "No prior threat intelligence matches."
        )

        rule_hit_items: list[str] = []
        for hit in url_detection_hits or []:
            rule_hit_items.append(
                f"- [{hit.rule_id}] {hit.title} "
                f"(Severity: {hit.severity.value.upper()}, Confidence: {hit.confidence}): "
                f"{hit.description}"
            )
        rules_block = (
            "\n".join(rule_hit_items)
            if rule_hit_items
            else "No deterministic detection rules fired."
        )

        user_prompt = (
            f"Investigation Title: {ctx.investigation.title}\n"
            f"Target Type: {ctx.investigation.target_type}\n"
            f"Target Value: {ctx.investigation.target_value}\n"
            f"{target_breakdown}\n"
            f"Attached Artifacts:\n{artifact_block}\n\n"
            f"Extracted Indicators ({len(collected)} total):\n{ioc_block}\n\n"
            f"Threat Intelligence Evaluation Feed:\n{ti_block}\n\n"
            f"Deterministic Detection Rules Fired:\n{rules_block}\n\n"
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
        url_detection_hits: list[UrlDetectionHit] | None = None,
    ) -> TriageAnalysis:
        """Deterministic rule-based triage used when model router is unavailable."""
        has_auth_log = any(a.kind in {"linux_auth_log", "syslog"} for a in ctx.artifacts)
        is_auth_target = ctx.investigation.target_type_enum == TargetType.LOG

        hits = url_detection_hits or []
        crit_hit = next((h for h in hits if h.severity == Severity.CRITICAL), None)
        high_hit = next((h for h in hits if h.severity == Severity.HIGH), None)
        legit_hit = next((h for h in hits if h.rule_id == RULE_LEGITIMATE_DOMAIN), None)

        if crit_hit:
            category = "credential_phishing_campaign"
            summary = crit_hit.title
            severity = Severity.CRITICAL
            confidence = crit_hit.confidence
            reasoning = crit_hit.reasoning
        elif high_hit:
            category = "phishing_attempt"
            summary = high_hit.title
            severity = Severity.HIGH
            confidence = high_hit.confidence
            reasoning = high_hit.reasoning
        elif legit_hit:
            category = "authorized_enterprise_service"
            summary = legit_hit.title
            severity = Severity.INFO
            confidence = 0.99
            reasoning = legit_hit.reasoning
        elif has_auth_log or is_auth_target:
            category = "authentication_attack"
            summary = "Authentication log submission containing login and session events."
            severity = Severity.INFO
            confidence = 0.85
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
            confidence = 0.85
            reasoning = (
                "Network identifier provided without local logs; requires reputation lookup."
            )
        elif ctx.investigation.target_type_enum in {TargetType.HASH, TargetType.FILE}:
            category = "malware_suspect"
            summary = (
                f"File/hash target ({ctx.investigation.target_value}) submitted for inspection."
            )
            severity = Severity.INFO
            confidence = 0.85
            reasoning = "File or hash indicator submitted; requires static/dynamic analysis."
        else:
            category = "incident_triage"
            summary = f"Initial triage for investigation '{ctx.investigation.title}'."
            severity = Severity.INFO
            confidence = 0.85
            reasoning = "Baseline extraction completed; awaiting further evidence."

        classification = InputClassification(
            category=category,
            summary=summary,
            confidence=confidence,
            initial_severity=severity,
            reasoning=reasoning,
        )

        entities: list[ExtractedEntity] = []
        indicators: list[IndicatorAssessment] = []
        seen_entities: set[tuple[str, str]] = set()

        for row in collected:
            val = str(
                row.data.get("value") or row.data.get("match") or row.data.get("indicator") or ""
            )
            ioc_type = str(row.data.get("ioc_type") or row.data.get("indicator_type") or "unknown")
            scope = str(row.data.get("scope") or "global")
            if val and (ioc_type, val) not in seen_entities:
                seen_entities.add((ioc_type, val))
                is_target_str = val == ctx.investigation.target_value.strip()
                if legit_hit and (val in legit_hit.title or is_target_str):
                    role = "verified_service"
                    threat_assess = "verified_legitimate"
                    is_mal = False
                elif (crit_hit or high_hit) and (is_target_str or "phish" in category):
                    role = "deceptive_infrastructure"
                    threat_assess = "active_phishing_campaign"
                    is_mal = True
                else:
                    role = "attacker" if scope == "global" else "target_or_internal"
                    threat_assess = "unverified_external" if scope == "global" else "internal_asset"
                    is_mal = scope == "global"

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
                        threat_assessment=threat_assess,
                        is_malicious_candidate=is_mal,
                    )
                )

        gaps: list[EvidenceGap] = []
        if global_indicators and not legit_hit:
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
        if crit_hit or high_hit:
            plan.append(
                PlannedTaskProposal(
                    task_type="mitre",
                    rationale=(
                        "Map detected phishing and brand impersonation rules to verified "
                        "MITRE ATT&CK techniques (T1566.002, T1583.001)"
                    ),
                    priority=prio,
                )
            )
            prio += 1
        elif has_auth_log:
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
        url_detection_hits: list[UrlDetectionHit] | None = None,
        is_model_driven: bool = False,
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

        # 2. Report what the local evaluation feed contains, not a live verdict.
        for ti_ev in threat_intel_evidence or []:
            data = ti_ev.data or {}
            indicator = str(data.get("indicator") or "unknown")
            reputation_status = str(data.get("reputation_status", "unknown"))
            is_mal = reputation_status == "malicious"
            source = str(data.get("source", "ThreatIntel"))
            raw_score = data.get("abuse_score")
            score = int(raw_score) if raw_score is not None else None
            category = str(data.get("category", "Threat Intelligence"))
            reports = int(data.get("reports_count", 0))

            if is_mal:
                finding_ti = await ctx.store.add_finding(
                    FindingDraft(
                        title=f"Demo Feed Alert: {indicator} ({category})",
                        description=(
                            f"Indicator '{indicator}' is flagged as malicious by the "
                            f"{source} feed with an abuse score of {score}% ({reports} report(s)). "
                            f"Threat Category: {category}. These are synthetic evaluation "
                            "values; no external provider was queried."
                        ),
                        assertion_class=AssertionClass.FACT,
                        severity=Severity.HIGH,
                        confidence=min(1.0, max(0.8, (score or 0) / 100.0)),
                        evidence_ids=[ti_ev.id],
                        detection_rule="threat_intel.reputation",
                    ),
                    agent_run_id=ctx.agent_run_id,
                )
                findings.append(str(finding_ti.id))
            elif (
                reputation_status == "benign"
                and indicator == ctx.investigation.target_value.strip()
            ):
                finding_ti = await ctx.store.add_finding(
                    FindingDraft(
                        title=f"Demo Feed: {indicator} (Benign Test Entry)",
                        description=(
                            f"Indicator '{indicator}' was checked against the {source} feed. "
                            f"The synthetic entry has an abuse score of {score}%. "
                            "This is not a real-world safety verdict."
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

            elif (
                reputation_status == "unknown"
                and indicator == ctx.investigation.target_value.strip()
            ):
                finding_ti = await ctx.store.add_finding(
                    FindingDraft(
                        title=f"Threat Intelligence: {indicator} (Unknown)",
                        description=(
                            f"Indicator '{indicator}' is absent from the {source} feed. "
                            "No external reputation lookup was performed; maliciousness is unknown."
                        ),
                        assertion_class=AssertionClass.UNKNOWN,
                        severity=Severity.INFO,
                        confidence=1.0,
                        evidence_ids=[ti_ev.id],
                        detection_rule="threat_intel.reputation",
                    ),
                    agent_run_id=ctx.agent_run_id,
                )
                findings.append(str(finding_ti.id))

        # 2b. URL and Domain Detection Rule Hits (INFERENCE / FACT, G1/G2 compliant)
        for hit in url_detection_hits or []:
            finding_hit = await ctx.store.add_finding(
                FindingDraft(
                    title=hit.title,
                    description=hit.description,
                    assertion_class=(
                        AssertionClass.FACT
                        if hit.rule_id == RULE_LEGITIMATE_DOMAIN
                        else AssertionClass.INFERENCE
                    ),
                    severity=hit.severity,
                    confidence=hit.confidence,
                    evidence_ids=hit.evidence_ids,
                    reasoning=hit.reasoning,
                    detection_rule=hit.rule_id,
                ),
                agent_run_id=ctx.agent_run_id,
            )
            findings.append(str(finding_hit.id))

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
        detection_rule = (
            "triage.classification" if is_model_driven else "triage.deterministic_fallback"
        )
        if collected:
            finding_cls = await ctx.store.add_finding(
                FindingDraft(
                    title=f"Triage Assessment: {formatted_cat}",
                    description=analysis.classification.summary,
                    assertion_class=AssertionClass.INFERENCE,
                    severity=analysis.classification.initial_severity,
                    confidence=analysis.classification.confidence,
                    evidence_ids=[row.id for row in collected[:_MAX_CITED]],
                    reasoning=analysis.classification.reasoning,
                    detection_rule=detection_rule,
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
                    severity=analysis.classification.initial_severity,
                    confidence=analysis.classification.confidence,
                    reasoning=analysis.classification.reasoning,
                    detection_rule=detection_rule,
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
