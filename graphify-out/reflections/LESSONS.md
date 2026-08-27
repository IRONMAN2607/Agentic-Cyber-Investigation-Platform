# Lessons & Work Memory
## Preferred Sources
- `src_acip_db_models_evidence` (Evidence ORM model): Central bridge node connecting data intake, parsing, agent execution, invariants enforcement, and API reporting.

## Query Traces
- **Question**: Why does Evidence connect 8 communities?
- **Answer**: `Evidence` (`src/acip/db/models.py`) is AACIP's foundational provenance record. It connects:
  1. ORM Declarative Models via inheritance from `Base`.
  2. Artifact Intake & Tool Execution via tool runs producing raw evidence from ingested files.
  3. Linux Auth Log Parser via parser output (`TimeConfidence`, `EvidenceDraft`).
  4. Evidence & Finding Store via `EvidenceStore` enforcing G0-G4 grounding invariants and persisting records.
  5. Agent Implementations & Execution via `LogAnalysisAgent`, `TriageAgent` recording observations.
  6. Reporting Agent & Markdown via `ReportAgent` reading evidence for timelines and indicators.
  7. API Schemas & Query Endpoints via `/investigations/{id}/evidence` paginated responses.
- **Outcome**: useful
