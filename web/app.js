(() => {
  "use strict";

  const API_BASE = "/api/v1";
  let currentToken = localStorage.getItem("acip_token") || "";
  let currentInvId = null;
  let pollInterval = null;

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
    ws.innerHTML = `<div style="padding: 2rem; text-align: center; color: var(--text-muted);">Loading workspace...</div>`;

    if (pollInterval) clearInterval(pollInterval);

    try {
      const detail = await api(`/investigations/${id}`);
      renderWorkspace(detail);

      if (detail.investigation.status === "running") {
        pollInterval = setInterval(async () => {
          if (currentInvId !== id) {
            clearInterval(pollInterval);
            return;
          }
          const fresh = await api(`/investigations/${id}`);
          renderWorkspace(fresh);
          if (fresh.investigation.status !== "running") {
            clearInterval(pollInterval);
            loadInvestigations();
          }
        }, 1500);
      }
    } catch (e) {
      ws.innerHTML = `<div style="padding: 2rem; color: var(--sev-critical);">Error loading workspace: ${escapeHtml(e.message)}</div>`;
    }
  }

  function renderWorkspace(data) {
    const inv = data.investigation;
    const ws = document.getElementById("workspace-view");

    ws.innerHTML = `
      <!-- Hero -->
      <div class="hero-banner">
        <div class="hero-info">
          <h2>${escapeHtml(inv.title)}</h2>
          <div class="hero-meta">
            <span>ID: <code>${inv.display_id}</code></span>
            <span>Target: <strong>${escapeHtml(inv.target_type)}</strong> (${escapeHtml(inv.target_value)})</span>
            <span>Status: <span class="badge badge-${inv.status}">${inv.status}</span></span>
          </div>
        </div>
        <div style="display: flex; gap: 0.5rem;">
          ${inv.status === "created" ? `
            <button class="btn btn-secondary" onclick="window.acipOpenUpload('${inv.id}')">+ Upload Artifact</button>
            <button class="btn btn-primary" onclick="window.acipStartInvestigation('${inv.id}')">▶ Start Run</button>
          ` : `
            <button class="btn btn-outline" onclick="window.acipSelect('${inv.id}')">↻ Refresh</button>
          `}
        </div>
      </div>

      <!-- Metrics -->
      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-label">Severity</div>
          <div class="metric-value">
            <span class="badge badge-${inv.severity || 'info'}" style="font-size: 1rem; padding: 0.35rem 0.75rem;">
              ${inv.severity ? inv.severity.toUpperCase() : 'N/A'}
            </span>
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Risk Score</div>
          <div class="metric-value" style="color: ${inv.risk_score > 50 ? 'var(--sev-high)' : 'var(--brand-primary)'}">
            ${inv.risk_score !== null ? inv.risk_score : '-'} <span style="font-size: 0.9rem; color: var(--text-muted);">/ 100</span>
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Artifacts</div>
          <div class="metric-value">${data.counts.artifacts}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Findings</div>
          <div class="metric-value">${data.counts.findings}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Evidence Items</div>
          <div class="metric-value">${data.counts.evidence}</div>
        </div>
      </div>

      <!-- Findings Section -->
      <div class="section-card">
        <div class="section-card-header">
          <span>Grounded Findings (${data.findings.length})</span>
        </div>
        <div class="findings-list">
          ${data.findings.length === 0 ? `<div style="color: var(--text-muted); font-size: 0.9rem;">No findings recorded yet.</div>` : data.findings.map(f => `
            <div class="finding-card">
              <div class="finding-header">
                <span class="finding-title">${escapeHtml(f.title)}</span>
                <div style="display: flex; gap: 0.5rem; align-items: center;">
                  <span class="badge badge-info">${f.assertion_class}</span>
                  <span class="badge badge-${f.severity}">${f.severity}</span>
                  <span style="font-size: 0.8rem; color: var(--text-muted);">Conf: ${(f.confidence * 100).toFixed(0)}%</span>
                </div>
              </div>
              <p class="finding-desc">${escapeHtml(f.description)}</p>
              ${f.reasoning ? `<div class="finding-reasoning"><strong>Reasoning:</strong> ${escapeHtml(f.reasoning)}</div>` : ''}
              <div class="chips-list">
                ${f.evidence_ids.map(eid => `<span class="chip">Cited: ${eid.slice(0, 8)}...</span>`).join('')}
              </div>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Execution Trace -->
      <div class="section-card">
        <div class="section-card-header">
          <span>Execution Trace</span>
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th>Agent / Tool</th>
              <th>Type</th>
              <th>Status</th>
              <th>Duration</th>
              <th>Outcome / Rationale</th>
            </tr>
          </thead>
          <tbody>
            ${data.agent_runs.map(ar => `
              <tr>
                <td><strong>${escapeHtml(ar.agent_name)}</strong> (v${ar.agent_version})</td>
                <td><span class="badge badge-info">AGENT</span></td>
                <td><span class="badge badge-${ar.status}">${ar.status}</span></td>
                <td>${ar.duration_ms !== null ? ar.duration_ms + 'ms' : '-'}</td>
                <td>${escapeHtml(ar.rationale || '-')}</td>
              </tr>
            `).join('')}
            ${data.tool_runs.map(tr => `
              <tr>
                <td><code>${escapeHtml(tr.tool_name)}</code> (v${tr.tool_version})</td>
                <td><span class="badge badge-low">TOOL (${tr.sandbox_tier})</span></td>
                <td><span class="badge badge-${tr.status}">${tr.status}</span></td>
                <td>${tr.duration_ms !== null ? tr.duration_ms + 'ms' : '-'}</td>
                <td>Produced ${tr.evidence_count} evidence item(s)</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <!-- Report Section -->
      ${data.report ? `
        <div class="section-card">
          <div class="section-card-header">
            <span>Executive Investigation Report</span>
            <button class="btn btn-outline btn-sm" onclick="navigator.clipboard.writeText(document.getElementById('report-text').textContent)">Copy Report</button>
          </div>
          <div style="padding: 1rem;">
            <pre id="report-text" class="report-content">${escapeHtml(data.report.content)}</pre>
          </div>
        </div>
      ` : ''}
    `;
  }

  // --- Global Handlers for inline UI onclick ---
  window.acipSelect = selectInvestigation;
  window.acipOpenUpload = (invId) => {
    document.getElementById("upload-inv-id").value = invId;
    document.getElementById("modal-upload-artifact").showModal();
  };
  window.acipStartInvestigation = async (invId) => {
    try {
      await api(`/investigations/${invId}/start`, { method: "POST" });
      selectInvestigation(invId);
    } catch (e) {
      alert(`Could not start run: ${e.message}`);
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
      loadInvestigations();
    } catch (err) {
      alert(`Login failed: ${err.message}`);
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
      await loadInvestigations();
      selectInvestigation(inv.id);
    } catch (err) {
      alert(`Failed to create investigation: ${err.message}`);
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
      selectInvestigation(invId);
    } catch (err) {
      alert(`Upload failed: ${err.message}`);
    }
  });

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
