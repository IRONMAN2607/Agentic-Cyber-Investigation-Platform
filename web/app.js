(() => {
  "use strict";

  const API_BASE = "/api/v1";
  let currentToken = localStorage.getItem("acip_token") || "";
  let currentInvId = null;
  let pollInterval = null;
  let activeTab = "all";

  // --- API Client ---
  async function api(path, options = {}) {
    const headers = options.headers || {};
    if (currentToken && !headers["Authorization"]) {
      headers["Authorization"] = `Bearer ${currentToken}`;
    }
    if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }

    const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
    if (res.status === 401 && path !== "/auth/login") {
      setAuth("", null);
      showLogin();
      throw new Error("Session expired. Please log in.");
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({ message: res.statusText }));
      throw new Error(err.message || "Request failed");
    }
    return res.json();
  }

  // --- Auth State ---
  function setAuth(token, user) {
    currentToken = token;
    if (token) {
      localStorage.setItem("acip_token", token);
      if (user) {
        document.getElementById("user-display").textContent = `${user.username} (${user.role})`;
      }
      document.getElementById("btn-login-modal").style.display = "none";
      document.getElementById("btn-logout").style.display = "inline-flex";
    } else {
      localStorage.removeItem("acip_token");
      document.getElementById("user-display").textContent = "Not Logged In";
      document.getElementById("btn-login-modal").style.display = "inline-flex";
      document.getElementById("btn-logout").style.display = "none";
    }
  }

  async function checkCurrentUser() {
    if (!currentToken) return;
    try {
      const user = await api("/auth/me");
      setAuth(currentToken, user);
      loadInvestigations();
    } catch {
      setAuth("", null);
    }
  }

  function showLogin() {
    const modal = document.getElementById("modal-login");
    if (modal) modal.showModal();
  }

  // --- Investigations List ---
  async function loadInvestigations() {
    const listEl = document.getElementById("inv-list");
    try {
      const invs = await api("/investigations");
      if (!invs || invs.length === 0) {
        listEl.innerHTML = `<li style="padding: 1.5rem; text-align: center; color: var(--text-muted);">No investigations found.</li>`;
        return;
      }
      listEl.innerHTML = invs.map(inv => `
        <li class="inv-item ${inv.id === currentInvId ? 'active' : ''}" data-id="${inv.id}">
          <div class="inv-item-title">${escapeHtml(inv.title)}</div>
          <div class="inv-item-meta">
            <span class="badge badge-${inv.status}">${inv.status}</span>
            <span>${new Date(inv.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
          </div>
        </li>
      `).join("");

      listEl.querySelectorAll(".inv-item").forEach(item => {
        item.addEventListener("click", () => {
          selectInvestigation(item.dataset.id);
        });
      });
    } catch (e) {
      listEl.innerHTML = `<li style="padding: 1rem; color: var(--sev-critical);">${escapeHtml(e.message)}</li>`;
    }
  }

  // --- Workspace Detail ---
  async function selectInvestigation(id) {
    currentInvId = id;
    loadInvestigations();
    const ws = document.getElementById("workspace-view");
    ws.innerHTML = `<div style="padding: 3rem; text-align: center; color: var(--text-muted);">Loading investigation workspace...</div>`;

    if (pollInterval) clearInterval(pollInterval);

    try {
      const [detail, evidenceData] = await Promise.all([
        api(`/investigations/${id}`),
        api(`/investigations/${id}/evidence?limit=100`).catch(() => ({ items: [] }))
      ]);

      renderWorkspace(detail, evidenceData.items || []);

      if (detail.investigation.status === "running") {
        pollInterval = setInterval(async () => {
          if (currentInvId !== id) {
            clearInterval(pollInterval);
            return;
          }
          const [freshDetail, freshEvidence] = await Promise.all([
            api(`/investigations/${id}`),
            api(`/investigations/${id}/evidence?limit=100`).catch(() => ({ items: [] }))
          ]);
          renderWorkspace(freshDetail, freshEvidence.items || []);
          if (freshDetail.investigation.status !== "running") {
            clearInterval(pollInterval);
            loadInvestigations();
          }
        }, 1500);
      }
    } catch (e) {
      ws.innerHTML = `<div style="padding: 2rem; color: var(--sev-critical);">Error loading workspace: ${escapeHtml(e.message)}</div>`;
    }
  }

  function renderWorkspace(data, evidenceItems = []) {
    const inv = data.investigation;
    const ws = document.getElementById("workspace-view");

    ws.innerHTML = `
      <!-- Hero Banner -->
      <div class="hero-banner">
        <div class="hero-info">
          <h2>${escapeHtml(inv.title)}</h2>
          <div class="hero-meta">
            <span>ID: <code>${escapeHtml(inv.display_id)}</code></span>
            <span>Target: <strong>${escapeHtml(inv.target_type)}</strong> (<code>${escapeHtml(inv.target_value)}</code>)</span>
            <span>Status: <span class="badge badge-${inv.status}">${inv.status}</span></span>
          </div>
        </div>
        <div style="display: flex; gap: 0.6rem; align-items: center;">
          ${inv.status === "created" ? `
            <button class="btn btn-secondary" onclick="window.acipOpenUpload('${inv.id}')">+ Upload Artifact</button>
            <button class="btn btn-primary" onclick="window.acipStartInvestigation('${inv.id}')">▶ Start Run</button>
          ` : `
            <button class="btn btn-outline" onclick="window.acipSelect('${inv.id}')">↻ Refresh</button>
          `}
          <button class="btn btn-outline btn-sm" style="color: #f87171; border-color: rgba(239, 68, 68, 0.35);" onclick="window.acipDeleteInvestigation('${inv.id}', '${escapeHtml(inv.title)}')" title="Delete & Purge this Investigation">🗑 Delete</button>
        </div>
      </div>

      ${inv.status === "running" ? `
        <div class="progress-container">
          <div class="progress-header">
            <span>Investigation pipeline executing tasks...</span>
            <span class="pulse-indicator"></span>
          </div>
          <div class="progress-track">
            <div class="progress-bar-fill"></div>
          </div>
        </div>
      ` : ''}

      <!-- Quick Navigation Tabs -->
      <div class="workspace-nav">
        <button class="nav-tab ${activeTab === 'all' ? 'active' : ''}" onclick="window.acipSetTab('all')">Overview (All)</button>
        <button class="nav-tab ${activeTab === 'findings' ? 'active' : ''}" onclick="window.acipSetTab('findings')">Findings (${data.findings.length})</button>
        <button class="nav-tab ${activeTab === 'evidence' ? 'active' : ''}" onclick="window.acipSetTab('evidence')">Evidence (${data.counts.evidence || evidenceItems.length})</button>
        <button class="nav-tab ${activeTab === 'trace' ? 'active' : ''}" onclick="window.acipSetTab('trace')">Execution Trace (${data.agent_runs.length + data.tool_runs.length})</button>
        ${data.report ? `<button class="nav-tab ${activeTab === 'report' ? 'active' : ''}" onclick="window.acipSetTab('report')">Incident Report</button>` : ''}
      </div>

      <!-- Metrics Cards Grid -->
      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-label">Severity Level</div>
          <div class="metric-value">
            <span class="badge badge-${inv.severity || 'info'}" style="font-size: 0.95rem; padding: 0.35rem 0.75rem;">
              ${inv.severity ? inv.severity.toUpperCase() : 'N/A'}
            </span>
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Calculated Risk</div>
          <div class="metric-value" style="color: ${inv.risk_score > 50 ? 'var(--sev-high)' : 'var(--brand-primary)'}">
            ${inv.risk_score !== null ? inv.risk_score : '-'} <span style="font-size: 0.9rem; color: var(--text-muted); font-weight: 400;">/ 100</span>
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Artifacts Stored</div>
          <div class="metric-value">${data.counts.artifacts}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Grounded Findings</div>
          <div class="metric-value">${data.counts.findings}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Evidence Items</div>
          <div class="metric-value">${data.counts.evidence}</div>
        </div>
      </div>

      <!-- Grounded Findings Section -->
      <div id="section-findings" class="section-card" style="display: ${activeTab === 'all' || activeTab === 'findings' ? 'block' : 'none'};">
        <div class="section-card-header">
          <span>Grounded Findings (${data.findings.length})</span>
          <span style="font-size: 0.75rem; color: var(--text-muted);">Bound to deterministic evidence (G0–G4)</span>
        </div>
        <div class="findings-list">
          ${data.findings.length === 0 ? `<div style="color: var(--text-muted); font-size: 0.9rem; padding: 1rem 0;">No findings recorded yet. Run the investigation to evaluate detection rules.</div>` : data.findings.map(f => `
            <div class="finding-card" data-severity="${f.severity.toLowerCase()}">
              <div class="finding-header">
                <span class="finding-title">${escapeHtml(f.title)}</span>
                <div style="display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;">
                  <span class="badge badge-${f.assertion_class.toLowerCase()}">${f.assertion_class}</span>
                  <span class="badge badge-${f.severity}">${f.severity}</span>
                  <span style="font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono);">Conf: ${(f.confidence * 100).toFixed(0)}%</span>
                </div>
              </div>
              <p class="finding-desc">${escapeHtml(f.description)}</p>
              ${f.reasoning ? `<div class="finding-reasoning"><strong>Reasoning / Rule Logic:</strong> ${escapeHtml(f.reasoning)}</div>` : ''}
              ${f.evidence_ids && f.evidence_ids.length > 0 ? `
                <div class="chips-list">
                  <span style="color: var(--text-muted); font-weight: 500;">Cited Evidence:</span>
                  ${f.evidence_ids.map(eid => `
                    <button class="chip" style="cursor: pointer;" onclick="window.acipInspectProvenance('${inv.id}', '${eid}')" title="Click to view Cryptographic Provenance Chain">
                      🔍 ${eid.slice(0, 8)}...
                    </button>
                  `).join('')}
                </div>
              ` : ''}
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Grounded Evidence Items Section -->
      <div id="section-evidence" class="section-card" style="display: ${activeTab === 'all' || activeTab === 'evidence' ? 'block' : 'none'};">
        <div class="section-card-header">
          <span>Grounded Evidence Stream (${evidenceItems.length || data.counts.evidence})</span>
          <span style="font-size: 0.75rem; color: var(--text-muted);">Immutable append-only records with provenance</span>
        </div>
        <div class="table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Evidence ID / Hash</th>
                <th>Source Tool</th>
                <th>Kind</th>
                <th>Observed At</th>
                <th>Confidence</th>
                <th>Payload Summary</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${evidenceItems.length === 0 ? `
                <tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No evidence records collected yet.</td></tr>
              ` : evidenceItems.map(ev => `
                <tr>
                  <td><code>${ev.id.slice(0, 8)}...</code></td>
                  <td><strong>${escapeHtml(ev.source_tool)}</strong></td>
                  <td><span class="badge badge-info">${escapeHtml(ev.kind)}</span></td>
                  <td>${ev.observed_at ? new Date(ev.observed_at).toLocaleString() : 'N/A'} <span style="font-size: 0.7rem; color: var(--text-muted);">(${ev.time_confidence})</span></td>
                  <td>${(ev.confidence * 100).toFixed(0)}%</td>
                  <td style="max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(JSON.stringify(ev.data))}">
                    ${escapeHtml(JSON.stringify(ev.data))}
                  </td>
                  <td>
                    <button class="btn btn-outline btn-sm" onclick="window.acipInspectProvenance('${inv.id}', '${ev.id}')">
                      Provenance
                    </button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Execution Trace Section -->
      <div id="section-trace" class="section-card" style="display: ${activeTab === 'all' || activeTab === 'trace' ? 'block' : 'none'};">
        <div class="section-card-header">
          <span>Execution Trace & Agent Coordination</span>
          <span style="font-size: 0.75rem; color: var(--text-muted);">Audited execution steps emitted for evaluation</span>
        </div>
        <div class="table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Component / Name</th>
                <th>Class</th>
                <th>Status</th>
                <th>Duration</th>
                <th>Outcome / Audit Rationale</th>
              </tr>
            </thead>
            <tbody>
              ${data.agent_runs.length === 0 && data.tool_runs.length === 0 ? `
                <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No agent or tool executions recorded yet.</td></tr>
              ` : ''}
              ${data.agent_runs.map(ar => `
                <tr>
                  <td><strong>${escapeHtml(ar.agent_name)}</strong> <span style="font-size: 0.75rem; color: var(--text-muted);">(v${ar.agent_version})</span></td>
                  <td><span class="badge badge-inference">AGENT</span></td>
                  <td><span class="badge badge-${ar.status}">${ar.status}</span></td>
                  <td>${ar.duration_ms !== null ? ar.duration_ms + 'ms' : '-'}</td>
                  <td>${escapeHtml(ar.rationale || 'Agent execution completed successfully')}</td>
                </tr>
              `).join('')}
              ${data.tool_runs.map(tr => `
                <tr>
                  <td><code>${escapeHtml(tr.tool_name)}</code> <span style="font-size: 0.75rem; color: var(--text-muted);">(v${tr.tool_version})</span></td>
                  <td><span class="badge badge-low">TOOL (${tr.sandbox_tier})</span></td>
                  <td><span class="badge badge-${tr.status}">${tr.status}</span></td>
                  <td>${tr.duration_ms !== null ? tr.duration_ms + 'ms' : '-'}</td>
                  <td>Produced <strong>${tr.evidence_count}</strong> evidence item(s)</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Executive Report Section -->
      ${data.report ? `
        <div id="section-report" class="section-card" style="display: ${activeTab === 'all' || activeTab === 'report' ? 'block' : 'none'};">
          <div class="section-card-header">
            <span>Executive Investigation Report</span>
            <div style="display: flex; gap: 0.5rem;">
              <button id="btn-toggle-raw-report" class="btn btn-outline btn-sm" onclick="window.acipToggleReportView()">View Raw Markdown</button>
              <button id="btn-copy-report" class="btn btn-primary btn-sm" onclick="window.acipCopyReport()">Copy Report</button>
            </div>
          </div>
          <div id="report-rendered-view" class="report-body">
            ${renderMarkdown(data.report.content)}
          </div>
          <div id="report-raw-view" style="display: none; padding: 1rem;">
            <pre id="report-text" class="report-content">${escapeHtml(data.report.content)}</pre>
          </div>
        </div>
      ` : ''}
    `;
  }

  // --- Simple Markdown Formatter ---
  function renderMarkdown(md) {
    if (!md) return "";
    let html = escapeHtml(md);

    // Headers
    html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

    // Blockquotes
    html = html.replace(/^\> (.*$)/gim, '<blockquote>$1</blockquote>');

    // Bold & Italic
    html = html.replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>');
    html = html.replace(/\*(.*?)\*/gim, '<em>$1</em>');

    // Inline Code
    html = html.replace(/`([^`]+)`/gim, '<code>$1</code>');

    // Unordered List items
    html = html.replace(/^\- (.*$)/gim, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');

    // Newlines to paragraph breaks
    html = html.replace(/\n\n/g, '<br><br>');

    return html;
  }

  // --- Global Window Handlers ---
  window.acipSelect = selectInvestigation;
  window.acipSetTab = (tab) => {
    activeTab = tab;
    if (currentInvId) selectInvestigation(currentInvId);
  };

  window.acipOpenUpload = (invId) => {
    document.getElementById("upload-inv-id").value = invId;
    document.getElementById("modal-upload-artifact").showModal();
  };

  window.acipStartInvestigation = async (invId) => {
    try {
      await api(`/investigations/${invId}/start`, { method: "POST" });
      showToast("Investigation started & queued", "info");
      selectInvestigation(invId);
    } catch (e) {
      showToast(`Could not start run: ${e.message}`, "error");
    }
  };

  window.acipCopyReport = () => {
    const rawEl = document.getElementById("report-text");
    if (!rawEl) return;
    navigator.clipboard.writeText(rawEl.textContent);
    showToast("Incident report copied to clipboard", "success");
    const btn = document.getElementById("btn-copy-report");
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = "✓ Copied!";
      setTimeout(() => { btn.textContent = orig; }, 2000);
    }
  };

  window.acipToggleReportView = () => {
    const rendered = document.getElementById("report-rendered-view");
    const raw = document.getElementById("report-raw-view");
    const btn = document.getElementById("btn-toggle-raw-report");
    if (raw.style.display === "none") {
      raw.style.display = "block";
      rendered.style.display = "none";
      btn.textContent = "View Rendered";
    } else {
      raw.style.display = "none";
      rendered.style.display = "block";
      btn.textContent = "View Raw Markdown";
    }
  };

  window.acipDeleteInvestigation = async (invId, title) => {
    if (!confirm(`Are you sure you want to delete / purge investigation "${title}"?\n\nThis will explicitly purge all associated evidence and audit records.`)) {
      return;
    }
    try {
      await api(`/investigations/${invId}?purge=true`, { method: "DELETE" });
      currentInvId = null;
      showToast("Investigation and evidence purged", "info");
      document.getElementById("workspace-view").innerHTML = `<div style="padding: 4rem 2rem; text-align: center; color: var(--text-muted);">Investigation deleted. Select another from the sidebar or click <strong>+ New</strong>.</div>`;
      await loadInvestigations();
    } catch (e) {
      showToast(`Could not delete investigation: ${e.message}`, "error");
    }
  };

  window.acipInspectProvenance = async (invId, evidenceId) => {
    const modal = document.getElementById("modal-provenance");
    const container = document.getElementById("provenance-details");
    container.innerHTML = `<div style="padding: 1rem; text-align: center; color: var(--text-muted);">Resolving provenance chain...</div>`;
    modal.showModal();

    try {
      const prov = await api(`/investigations/${invId}/evidence/${evidenceId}/provenance`);
      const ev = prov.evidence;
      const tool = prov.tool_run;
      const art = prov.artifact;
      const ag = prov.agent_run;

      container.innerHTML = `
        <div style="background-color: var(--bg-primary); padding: 0.85rem; border-radius: 6px; border: 1px solid var(--border-color);">
          <div style="font-weight: 700; color: var(--brand-primary); margin-bottom: 0.25rem;">1. Evidence Observation</div>
          <div>ID: <code>${ev.id}</code></div>
          <div>Kind: <strong>${escapeHtml(ev.kind)}</strong> (${ev.time_confidence})</div>
          <div>Content Hash: <code>${ev.content_hash}</code></div>
        </div>

        <div style="background-color: var(--bg-primary); padding: 0.85rem; border-radius: 6px; border: 1px solid var(--border-color);">
          <div style="font-weight: 700; color: #34d399; margin-bottom: 0.25rem;">2. Deterministic Tool Execution (G1 Compliance)</div>
          ${tool ? `
            <div>Tool: <strong>${escapeHtml(tool.tool_name)}</strong> (v${tool.tool_version})</div>
            <div>Run ID: <code>${tool.id}</code></div>
            <div>Sandbox Tier: <span class="badge badge-low">${tool.sandbox_tier}</span></div>
            <div>Status: <span class="badge badge-${tool.status}">${tool.status}</span> (${tool.duration_ms}ms)</div>
          ` : `<div style="color: var(--sev-critical);">No deterministic tool execution found!</div>`}
        </div>

        <div style="background-color: var(--bg-primary); padding: 0.85rem; border-radius: 6px; border: 1px solid var(--border-color);">
          <div style="font-weight: 700; color: #a5b4fc; margin-bottom: 0.25rem;">3. Source Artifact</div>
          ${art ? `
            <div>Filename: <code>${escapeHtml(art.original_filename)}</code></div>
            <div>SHA-256: <code>${art.sha256}</code></div>
            <div>Quarantine Size: ${art.size_bytes} bytes (${art.kind})</div>
          ` : `<div style="color: var(--text-muted);">No input artifact linked.</div>`}
        </div>

        ${prov.gaps && prov.gaps.length > 0 ? `
          <div style="background-color: rgba(239, 68, 68, 0.15); border: 1px solid var(--sev-critical); padding: 0.75rem; border-radius: 6px; color: #f87171;">
            <strong>Identified Gaps:</strong>
            <ul style="padding-left: 1.25rem; margin-top: 0.25rem;">
              ${prov.gaps.map(g => `<li>${escapeHtml(g)}</li>`).join('')}
            </ul>
          </div>
        ` : `
          <div style="color: #34d399; font-size: 0.8rem; display: flex; align-items: center; gap: 0.4rem;">
            ✓ Provenance chain is complete, verifiable, and G1 grounded.
          </div>
        `}
      `;
    } catch (e) {
      container.innerHTML = `<div style="color: var(--sev-critical); padding: 1rem;">Could not resolve provenance: ${escapeHtml(e.message)}</div>`;
    }
  };

  // --- Event Listeners ---
  document.getElementById("btn-login-modal").addEventListener("click", () => {
    document.getElementById("modal-login").showModal();
  });

  document.getElementById("btn-logout").addEventListener("click", () => {
    setAuth("", null);
    document.getElementById("inv-list").innerHTML = "";
    document.getElementById("workspace-view").innerHTML = `<div style="padding: 4rem 2rem; text-align: center; color: var(--text-muted);">Please log in to continue.</div>`;
  });

  document.getElementById("btn-new-inv").addEventListener("click", () => {
    if (!currentToken) {
      showLogin();
      return;
    }
    document.getElementById("modal-new-inv").showModal();
  });

  document.getElementById("form-login").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("login-username").value;
    const password = document.getElementById("login-password").value;
    try {
      const data = await api("/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      setAuth(data.access_token, data.user);
      document.getElementById("modal-login").close();
      showToast(`Welcome back, ${data.user.username}!`, "success");
      loadInvestigations();
    } catch (err) {
      showToast(`Login failed: ${err.message}`, "error");
    }
  });

  document.getElementById("form-new-inv").addEventListener("submit", async (e) => {
    e.preventDefault();
    const title = document.getElementById("inv-title").value;
    const target_type = document.getElementById("inv-target-type").value;
    const target_value = document.getElementById("inv-target-value").value;
    try {
      const inv = await api("/investigations", {
        method: "POST",
        body: JSON.stringify({ title, target_type, target_value }),
      });
      document.getElementById("modal-new-inv").close();
      showToast("Investigation created successfully", "success");
      await loadInvestigations();
      selectInvestigation(inv.id);
    } catch (err) {
      showToast(`Failed to create investigation: ${err.message}`, "error");
    }
  });

  document.getElementById("form-upload-artifact").addEventListener("submit", async (e) => {
    e.preventDefault();
    const invId = document.getElementById("upload-inv-id").value;
    const fileInput = document.getElementById("upload-file");
    const kind = document.getElementById("upload-kind").value;

    if (!fileInput.files[0]) return;

    const fd = new FormData();
    fd.append("file", fileInput.files[0]);
    fd.append("kind", kind);

    try {
      await api(`/investigations/${invId}/artifacts`, {
        method: "POST",
        body: fd,
      });
      document.getElementById("modal-upload-artifact").close();
      fileInput.value = "";
      showToast("Artifact uploaded & quarantined", "success");
      selectInvestigation(invId);
    } catch (err) {
      showToast(`Upload failed: ${err.message}`, "error");
    }
  });

  function showToast(message, type = "info", duration = 4000) {
    const container = document.getElementById("toast-container");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    const icon = type === "success" ? "✓" : type === "error" ? "⚠" : "ℹ";
    toast.innerHTML = `<span style="font-weight: 700; font-size: 1rem;">${icon}</span><span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    const dismiss = () => {
      if (toast.classList.contains("dismissing")) return;
      toast.classList.add("dismissing");
      toast.addEventListener("animationend", () => toast.remove(), { once: true });
    };

    setTimeout(dismiss, duration);
    toast.addEventListener("click", dismiss);
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // Auto-init on load
  checkCurrentUser();
})();
