const API_BASE_KEY = "astra_api_base";
const SESSION_KEY = "astra_session";
const SITES_KEY = "astra_sites";

const state = {
  view: "overview",
  session: readJson(SESSION_KEY, null),
  sites: readJson(SITES_KEY, []),
  health: {},
  events: {},
  selectedSiteId: null,
  selectedEvent: null,
  apiBase: localStorage.getItem(API_BASE_KEY) || "http://127.0.0.1:8000",
  loading: false,
};

const icons = {
  shield:
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-5"/></svg>',
  activity:
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
  plug:
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a6 6 0 0 1-12 0V8Z"/></svg>',
  server:
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 6h.01M6 18h.01"/></svg>',
  alert:
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.46 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4M12 17h.01"/></svg>',
  lock:
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  copy:
    '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>',
  refresh:
    '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 0 1-15.5 6.2L3 16"/><path d="M3 21v-5h5"/><path d="M3 12A9 9 0 0 1 18.5 5.8L21 8"/><path d="M21 3v5h-5"/></svg>',
  bolt:
    '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2 3 14h9l-1 8 10-12h-9l1-8Z"/></svg>',
  close:
    '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg>',
  logout:
    '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5c0-1.1.9-2 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/></svg>',
};

function readJson(key, fallback) {
  try {
    return JSON.parse(localStorage.getItem(key)) ?? fallback;
  } catch {
    return fallback;
  }
}

function saveSites() {
  localStorage.setItem(SITES_KEY, JSON.stringify(state.sites));
}

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatTime(value) {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function titleCase(value = "") {
  return String(value)
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

async function api(path, options = {}) {
  const response = await fetch(`${state.apiBase}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      message = body.detail || body.error || message;
    } catch {
      // Keep HTTP message.
    }
    throw new Error(message);
  }
  return response.json();
}

function currentSite() {
  return state.sites.find((site) => site.id === state.selectedSiteId) || state.sites[0] || null;
}

async function refreshAll() {
  if (!state.sites.length) {
    render();
    return;
  }
  await Promise.allSettled(state.sites.map((site) => refreshSite(site)));
  render();
}

async function refreshSite(site) {
  if (!site.dashboardToken) return;
  const headers = { Authorization: `Bearer ${site.dashboardToken}` };
  const [health, events] = await Promise.all([
    api(`/v1/sites/${site.id}/health`, { headers }),
    api(`/v1/sites/${site.id}/events?limit=50`, { headers }),
  ]);
  state.health[site.id] = health;
  state.events[site.id] = events.items || [];
}

async function createSite(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  state.loading = true;
  render();
  try {
    const created = await api("/v1/sites", {
      method: "POST",
      body: JSON.stringify({
        name: form.get("name"),
        domain: form.get("domain"),
        serverType: form.get("serverType"),
      }),
    });
    const site = {
      ...created.site,
      enrollmentToken: created.enrollmentToken,
      dashboardToken: created.dashboardToken,
      installCommand: created.installCommand,
    };
    state.sites = [site, ...state.sites.filter((item) => item.id !== site.id)];
    state.selectedSiteId = site.id;
    state.view = "sites";
    saveSites();
    toast("Website created. Install command is ready.");
    await refreshSite(site);
  } catch (error) {
    toast(error.message);
  } finally {
    state.loading = false;
    render();
  }
}

async function generateDemoThreat(site) {
  try {
    let agentToken = site.demoAgentToken;
    if (!agentToken) {
      const enrolled = await api("/v1/agents/enroll", {
        method: "POST",
        body: JSON.stringify({
          siteId: site.id,
          enrollToken: site.enrollmentToken,
          hostname: "dashboard-demo",
          version: "frontend-demo",
        }),
      });
      agentToken = enrolled.agentToken;
      site.demoAgentToken = agentToken;
      saveSites();
    }
    await api("/v1/agents/heartbeat", {
      method: "POST",
      body: JSON.stringify({ siteId: site.id, agentToken }),
    });
    await api("/v1/agents/events", {
      method: "POST",
      body: JSON.stringify({
        siteId: site.id,
        agentToken,
        events: [
          {
            attackType: "web_scan",
            severity: "high",
            sourceIp: "8.8.8.8",
            method: "GET",
            path: "/.env",
            statusCode: 404,
            userAgent: "curl/8 demo",
            ruleId: "suspicious_path",
            eventCount: 1,
            sampleLines: [
              '8.8.8.8 - - "GET /.env HTTP/1.1" 404 123 "-" "curl/8 demo"',
            ],
          },
        ],
      }),
    });
    await refreshSite(site);
    toast("Demo threat added. ASTRA marked it as danger.");
    render();
  } catch (error) {
    toast(error.message);
  }
}

async function copyText(text, message = "Copied.") {
  try {
    await navigator.clipboard.writeText(text);
    toast(message);
  } catch {
    toast("Clipboard permission was blocked.");
  }
}

function toast(message) {
  const existing = document.querySelector(".toast");
  if (existing) existing.remove();
  const item = document.createElement("div");
  item.className = "toast";
  item.textContent = message;
  document.body.appendChild(item);
  setTimeout(() => item.remove(), 3000);
}

function login(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  state.session = {
    name: form.get("name") || "ASTRA User",
    email: form.get("email") || "owner@example.com",
    at: new Date().toISOString(),
  };
  localStorage.setItem(SESSION_KEY, JSON.stringify(state.session));
  render();
  refreshAll();
}

function logout() {
  state.session = null;
  localStorage.removeItem(SESSION_KEY);
  render();
}

function setView(view, siteId = null) {
  state.view = view;
  if (siteId) state.selectedSiteId = siteId;
  render();
  if (view !== "connect") refreshAll();
}

function renderLogin() {
  return `
    <main class="login-shell">
      <section class="login-visual">
        <div class="brand-lockup">
          <div class="logo-mark">${icons.shield}</div>
          <span>ASTRA</span>
        </div>
        <div class="login-copy">
          <h1>Security that keeps watch after midnight.</h1>
          <p>Connect your Linux website server, let the agent watch traffic, and return to a dashboard that explains what happened, who was blocked, and what to improve next.</p>
        </div>
        <div class="metric-strip">
          <div class="glass-stat"><strong>24h</strong><span>temporary blocks</span></div>
          <div class="glass-stat"><strong>1</strong><span>health API</span></div>
          <div class="glass-stat"><strong>Live</strong><span>agent status</span></div>
        </div>
      </section>
      <section class="login-panel">
        <form class="auth-card" id="loginForm">
          <h2>Enter Dashboard</h2>
          <p>Temporary session for local testing. No user database is required for this frontend MVP.</p>
          <div class="field">
            <label for="name">Name</label>
            <input id="name" name="name" value="Site Owner" />
          </div>
          <div class="field">
            <label for="email">Email</label>
            <input id="email" name="email" type="email" value="owner@astra.local" />
          </div>
          <div class="field">
            <label for="password">Password</label>
            <input id="password" name="password" type="password" value="password" />
          </div>
          <button class="primary-btn full" type="submit">${icons.lock} Login</button>
        </form>
      </section>
    </main>
  `;
}

function renderShell() {
  const navItems = [
    ["overview", icons.activity, "Overview"],
    ["connect", icons.plug, "Connect Site"],
    ["sites", icons.server, "Protected Sites"],
    ["threats", icons.alert, "Threats"],
    ["guidance", icons.shield, "Prevention"],
    ["settings", icons.lock, "Settings"],
  ];
  const pageName = navItems.find(([key]) => key === state.view)?.[2] || "Overview";
  return `
    <main class="app-shell">
      <aside class="sidebar">
        <div class="brand-lockup">
          <div class="logo-mark">${icons.shield}</div>
          <span>ASTRA</span>
        </div>
        <nav class="nav">
          ${navItems
            .map(
              ([key, icon, label]) => `
                <button class="${state.view === key ? "active" : ""}" data-view="${key}">
                  ${icon}<span>${label}</span>
                </button>
              `
            )
            .join("")}
        </nav>
      </aside>
      <section class="workspace">
        <header class="topbar">
          <div class="page-title">
            <h1>${pageName}</h1>
            <span>${state.session.name} · ${state.session.email}</span>
          </div>
          <div class="row-actions">
            <button class="secondary-btn" data-action="refresh">${icons.refresh} Refresh</button>
            <button class="ghost-btn" data-action="logout">${icons.logout} Logout</button>
          </div>
        </header>
        <div class="content">${renderView()}</div>
      </section>
      ${renderDrawer()}
    </main>
  `;
}

function renderView() {
  if (state.view === "connect") return renderConnect();
  if (state.view === "sites") return renderSites();
  if (state.view === "threats") return renderThreats();
  if (state.view === "guidance") return renderGuidance();
  if (state.view === "settings") return renderSettings();
  return renderOverview();
}

function allHealth() {
  return state.sites.map((site) => state.health[site.id]).filter(Boolean);
}

function allEvents() {
  return state.sites.flatMap((site) =>
    (state.events[site.id] || []).map((event) => ({ ...event, siteName: site.name }))
  );
}

function renderOverview() {
  const healthList = allHealth();
  const danger = healthList.find((item) => item.status === "danger");
  const activeDangerCount = healthList.reduce((total, item) => total + (item.activeDangerCount || 0), 0);
  const activeBlocks = healthList.reduce((total, item) => total + (item.activeBlocks || 0), 0);
  const online = healthList.filter((item) => item.agentOnline).length;
  const statusWord = danger ? "Danger detected" : state.sites.length ? "Protected" : "Ready to connect";
  const heroCopy = danger
    ? "ASTRA found a dangerous event. Open the threat center to see the source IP, reason, action, and prevention advice."
    : state.sites.length
      ? "ASTRA is tracking your connected sites. Health and threat data refresh from the backend API."
      : "Create your first protected site and copy the installer command to connect the Linux agent.";

  return `
    <section class="hero-status">
      <div>
        <h2>${statusWord}</h2>
        <p>${heroCopy}</p>
      </div>
      <div class="hero-actions">
        <button class="secondary-btn" data-view="connect">${icons.plug} Add Site</button>
        <div class="status-orbit"><strong>${danger ? "!" : "OK"}</strong></div>
      </div>
    </section>
    <section class="grid stats-grid">
      ${statCard(icons.server, state.sites.length, "Protected sites", "var(--brand)")}
      ${statCard(icons.activity, online, "Agents online", "var(--green)")}
      ${statCard(icons.alert, activeDangerCount, "Active dangers", danger ? "var(--red)" : "var(--cyan)")}
      ${statCard(icons.lock, activeBlocks, "Active blocks", "var(--violet)")}
    </section>
    <section class="grid two-col">
      <div class="panel">
        <div class="section-title">
          <div><h2>Recent Threat Work</h2><span>What ASTRA handled recently</span></div>
          <button class="ghost-btn" data-view="threats">Open</button>
        </div>
        ${renderEventList(allEvents().slice(0, 5))}
      </div>
      <div class="panel">
        <div class="section-title">
          <div><h2>Protected Sites</h2><span>Connection and danger status</span></div>
          <button class="ghost-btn" data-view="sites">View</button>
        </div>
        ${renderMiniSites()}
      </div>
    </section>
  `;
}

function statCard(icon, value, label, color) {
  return `
    <article class="stat-card">
      <div class="icon" style="background:${color}">${icon}</div>
      <strong>${escapeHtml(value)}</strong>
      <span>${label}</span>
    </article>
  `;
}

function renderConnect() {
  return `
    <section class="grid two-col">
      <form class="panel" id="siteForm">
        <div class="section-title">
          <div><h2>Add Website</h2><span>Create a protected site and generate the agent command</span></div>
        </div>
        <div class="form-grid">
          <div class="field">
            <label>Website Name</label>
            <input name="name" placeholder="My Store" required />
          </div>
          <div class="field">
            <label>Domain</label>
            <input name="domain" placeholder="example.com" required />
          </div>
          <div class="field full">
            <label>Server Type</label>
            <select name="serverType">
              <option value="auto">Auto detect</option>
              <option value="nginx">Nginx</option>
              <option value="apache">Apache</option>
            </select>
          </div>
          <button class="primary-btn full" type="submit" ${state.loading ? "disabled" : ""}>
            ${icons.plug} ${state.loading ? "Creating..." : "Create Site"}
          </button>
        </div>
      </form>
      <div class="panel">
        <div class="section-title">
          <div><h2>Setup Path</h2><span>Designed for a non-technical handoff</span></div>
        </div>
        <div class="setup-list">
          ${setupStep(1, "Create the site record", "ASTRA stores the site, dashboard token, and enrollment token.")}
          ${setupStep(2, "Copy the command", "The command installs the agent service on the Linux VPS.")}
          ${setupStep(3, "Watch the status", "The dashboard turns online after the first heartbeat.")}
        </div>
      </div>
    </section>
    ${state.sites.length ? `<section class="panel">${renderInstallBox(currentSite() || state.sites[0])}</section>` : ""}
  `;
}

function setupStep(number, title, body) {
  return `
    <article class="setup-step">
      <div class="step-number">${number}</div>
      <div><strong>${title}</strong><p class="subtle">${body}</p></div>
    </article>
  `;
}

function renderInstallBox(site) {
  if (!site) return "";
  return `
    <div class="section-title">
      <div><h2>${escapeHtml(site.name)} Install Command</h2><span>${escapeHtml(site.domain || site.id)}</span></div>
      <button class="secondary-btn" data-copy="${escapeHtml(site.installCommand)}">${icons.copy} Copy</button>
    </div>
    <div class="command-box">
      <code>${escapeHtml(site.installCommand)}</code>
    </div>
  `;
}

function renderSites() {
  if (!state.sites.length) {
    return `<div class="empty-state"><div><strong>No sites connected yet</strong><span>Create a site to generate the ASTRA agent installer.</span><br><br><button class="primary-btn" data-view="connect">${icons.plug} Add Website</button></div></div>`;
  }
  return `
    <section class="grid site-grid">
      ${state.sites.map(renderSiteCard).join("")}
    </section>
  `;
}

function renderSiteCard(site) {
  const health = state.health[site.id] || {};
  const status = health.status || "pending";
  const pillClass = status === "danger" ? "danger" : status === "ok" ? "ok" : "pending";
  return `
    <article class="site-card">
      <header>
        <div>
          <h3>${escapeHtml(site.name)}</h3>
          <span class="subtle">${escapeHtml(site.domain || site.id)}</span>
        </div>
        <span class="pill ${pillClass}">${status.toUpperCase()}</span>
      </header>
      <div class="site-meta">
        <div class="meta-row"><span>Agent</span><strong>${health.agentOnline ? "Online" : "Offline/Pending"}</strong></div>
        <div class="meta-row"><span>Danger</span><strong>${health.dangerLevel || "none"}</strong></div>
        <div class="meta-row"><span>Blocks</span><strong>${health.activeBlocks || 0}</strong></div>
        <div class="meta-row"><span>Last heartbeat</span><strong>${formatTime(health.lastHeartbeatAt)}</strong></div>
      </div>
      <div class="row-actions">
        <button class="secondary-btn" data-site="${site.id}" data-view="threats">${icons.alert} Threats</button>
        <button class="ghost-btn" data-demo="${site.id}">${icons.bolt} Demo Threat</button>
        <button class="icon-btn" title="Copy install command" data-copy="${escapeHtml(site.installCommand)}">${icons.copy}</button>
      </div>
    </article>
  `;
}

function renderMiniSites() {
  if (!state.sites.length) {
    return `<div class="empty-state"><div><strong>No protected sites</strong><span>Your first site appears here after onboarding.</span></div></div>`;
  }
  return `<div class="site-meta">${state.sites
    .slice(0, 5)
    .map((site) => {
      const health = state.health[site.id] || {};
      return `<div class="meta-row"><span>${escapeHtml(site.name)}</span><strong>${health.status || "pending"}</strong></div>`;
    })
    .join("")}</div>`;
}

function renderThreats() {
  const site = currentSite();
  const siteEvents = site ? state.events[site.id] || [] : allEvents();
  return `
    <section class="grid two-col">
      <div class="panel">
        <div class="section-title">
          <div><h2>Threat Timeline</h2><span>${site ? escapeHtml(site.name) : "All sites"}</span></div>
          ${site ? `<button class="danger-btn" data-demo="${site.id}">${icons.bolt} Demo Threat</button>` : ""}
        </div>
        ${renderEventList(siteEvents)}
      </div>
      <div class="panel">
        <div class="section-title">
          <div><h2>Current Site</h2><span>Dashboard token based health</span></div>
        </div>
        ${site ? renderSiteCard(site) : `<div class="empty-state"><div><strong>Select a site</strong><span>Add a website first.</span></div></div>`}
      </div>
    </section>
  `;
}

function renderEventList(events) {
  if (!events.length) {
    return `<div class="empty-state"><div><strong>No threats recorded</strong><span>ASTRA will show detections, explanations, actions, and solutions here.</span></div></div>`;
  }
  return `<div class="event-list">${events.map(renderEventCard).join("")}</div>`;
}

function renderEventCard(event) {
  const severity = event.severity || "medium";
  const eventId = event.id || "";
  return `
    <article class="event-card">
      <div class="event-icon" style="background:${severity === "critical" || severity === "high" ? "var(--red)" : "var(--amber)"}">${icons.alert}</div>
      <div>
        <header>
          <div>
            <h3>${titleCase(event.attack_type || event.attackType || "Security Event")}</h3>
            <span class="subtle">${escapeHtml(event.source_ip || event.sourceIp || "Unknown IP")} · ${formatTime(event.timestamp || event.created_at)}</span>
          </div>
          <span class="severity ${severity}">${severity.toUpperCase()}</span>
        </header>
        <p>${escapeHtml(event.explanation || `Suspicious request against ${event.path || "the website"}.`)}</p>
        <div class="event-actions">
          <button class="secondary-btn" data-event="${escapeHtml(eventId)}">${icons.shield} Details</button>
        </div>
      </div>
    </article>
  `;
}

function renderGuidance() {
  const events = allEvents();
  const latest = events.slice(0, 3);
  return `
    <section class="grid three-col">
      ${recommendation("Brute Force", "Rate limit login pages, require strong passwords, and enable multi-factor authentication.", "var(--red)")}
      ${recommendation("Sensitive File Scans", "Keep .env, backups, and admin tools outside public web roots.", "var(--amber)")}
      ${recommendation("Request Floods", "Use server-level rate limits and keep temporary blocks enabled for high-severity sources.", "var(--cyan)")}
    </section>
    <section class="panel">
      <div class="section-title">
        <div><h2>Advice From Recent Events</h2><span>Generated by backend intelligence or local fallback</span></div>
      </div>
      ${
        latest.length
          ? latest
              .map(
                (event) => `
          <article class="setup-step">
            <div class="small-icon">${icons.shield}</div>
            <div>
              <strong>${titleCase(event.attack_type || "Security Event")}</strong>
              <ul class="solution-list">${parseSolutions(event.solutions)
                .map((solution) => `<li>${escapeHtml(solution)}</li>`)
                .join("")}</ul>
            </div>
          </article>
        `
              )
              .join("")
          : `<div class="empty-state"><div><strong>No event advice yet</strong><span>Generate a demo threat or connect the agent to see tailored recommendations.</span></div></div>`
      }
    </section>
  `;
}

function recommendation(title, body, color) {
  return `
    <article class="stat-card">
      <div class="icon" style="background:${color}">${icons.shield}</div>
      <strong style="font-size:20px">${title}</strong>
      <span>${body}</span>
    </article>
  `;
}

function parseSolutions(value) {
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function renderSettings() {
  return `
    <section class="panel">
      <div class="section-title">
        <div><h2>Frontend Settings</h2><span>Stored only in this browser</span></div>
      </div>
      <div class="form-grid">
        <div class="field full">
          <label>Backend API Base</label>
          <input id="apiBaseInput" value="${escapeHtml(state.apiBase)}" />
        </div>
        <button class="primary-btn" data-action="saveApiBase">${icons.lock} Save API Base</button>
        <button class="danger-btn" data-action="clearLocal">${icons.alert} Clear Local Session</button>
      </div>
    </section>
  `;
}

function renderDrawer() {
  const event = state.selectedEvent;
  if (!event) return `<div class="detail-drawer" id="drawer"></div>`;
  return `
    <div class="detail-drawer open" id="drawer">
      <aside class="drawer-panel">
        <header>
          <div>
            <h2>${titleCase(event.attack_type || event.attackType || "Security Event")}</h2>
            <span class="subtle">${escapeHtml(event.source_ip || event.sourceIp || "Unknown IP")}</span>
          </div>
          <button class="icon-btn" data-action="closeDrawer">${icons.close}</button>
        </header>
        <div class="kv">
          <div><span>Severity</span><strong>${escapeHtml(event.severity || "medium")}</strong></div>
          <div><span>Action</span><strong>${escapeHtml(event.action_taken || "Monitored")}</strong></div>
          <div><span>Path</span><strong>${escapeHtml(event.path || "Unknown")}</strong></div>
          <div><span>Rule</span><strong>${escapeHtml(event.rule_id || event.ruleId || "Unknown")}</strong></div>
          <div><span>Time</span><strong>${formatTime(event.timestamp || event.created_at)}</strong></div>
        </div>
        <h3>Explanation</h3>
        <p class="subtle">${escapeHtml(event.explanation || "No explanation provided.")}</p>
        <h3>Recommended Prevention</h3>
        <ul class="solution-list">
          ${parseSolutions(event.solutions)
            .map((solution) => `<li>${escapeHtml(solution)}</li>`)
            .join("") || "<li>Review server logs and keep protections enabled.</li>"}
        </ul>
      </aside>
    </div>
  `;
}

function bindEvents() {
  document.querySelector("#loginForm")?.addEventListener("submit", login);
  document.querySelector("#siteForm")?.addEventListener("submit", createSite);

  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.view, button.dataset.site));
  });

  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", () => copyText(button.dataset.copy, "Install command copied."));
  });

  document.querySelectorAll("[data-demo]").forEach((button) => {
    button.addEventListener("click", async () => {
      const site = state.sites.find((item) => item.id === button.dataset.demo);
      if (site) await generateDemoThreat(site);
    });
  });

  document.querySelectorAll("[data-event]").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedEvent = allEvents().find((event) => event.id === button.dataset.event);
      render();
    });
  });

  document.querySelector("[data-action='refresh']")?.addEventListener("click", refreshAll);
  document.querySelector("[data-action='logout']")?.addEventListener("click", logout);
  document.querySelector("[data-action='closeDrawer']")?.addEventListener("click", () => {
    state.selectedEvent = null;
    render();
  });
  document.querySelector("[data-action='saveApiBase']")?.addEventListener("click", () => {
    const value = document.querySelector("#apiBaseInput")?.value?.trim();
    if (value) {
      state.apiBase = value.replace(/\/$/, "");
      localStorage.setItem(API_BASE_KEY, state.apiBase);
      toast("API base saved.");
      refreshAll();
    }
  });
  document.querySelector("[data-action='clearLocal']")?.addEventListener("click", () => {
    localStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(SITES_KEY);
    state.session = null;
    state.sites = [];
    state.health = {};
    state.events = {};
    render();
  });
}

function render() {
  document.querySelector("#app").innerHTML = state.session ? renderShell() : renderLogin();
  bindEvents();
}

render();
if (state.session) refreshAll();
