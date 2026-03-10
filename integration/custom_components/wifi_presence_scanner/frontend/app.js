const API_BASE = window.WPS_API_BASE || "/v1";
const STORAGE_SCAN_RUNS_COLLAPSED = "wps_scan_runs_collapsed";
const STORAGE_HEALTH_COLLAPSED = "wps_health_collapsed";
const STORAGE_RULES_HELP_COLLAPSED = "wps_rules_help_collapsed";
const STORAGE_NOVEL_WINDOW_HOURS = "wps_novel_window_hours";
const STORAGE_NOVEL_MAX_SESSIONS = "wps_novel_max_sessions";

function loadCollapsedPreference(storageKey, defaultValue) {
  try {
    const raw = window.localStorage.getItem(storageKey);
    if (raw === null) {
      return defaultValue;
    }
    return raw === "true";
  } catch (_error) {
    return defaultValue;
  }
}

function saveCollapsedPreference(storageKey, collapsed) {
  try {
    window.localStorage.setItem(storageKey, String(collapsed));
  } catch (_error) {
    // Ignore storage write failures.
  }
}

function loadIntegerPreference(storageKey, defaultValue, minValue, maxValue) {
  try {
    const raw = window.localStorage.getItem(storageKey);
    if (raw === null) {
      return defaultValue;
    }
    const value = Math.trunc(Number(raw));
    if (!Number.isFinite(value)) {
      return defaultValue;
    }
    return Math.min(Math.max(value, minValue), maxValue);
  } catch (_error) {
    return defaultValue;
  }
}

const state = {
  networks: {
    limit: 100,
    offset: 0,
    items: [],
    sortKey: "last_seen",
    sortDirection: "desc",
  },
  runs: {
    limit: 50,
    offset: 0,
    items: [],
  },
  novel: {
    limit: 100,
    offset: 0,
    windowHours: loadIntegerPreference(STORAGE_NOVEL_WINDOW_HOURS, 24, 1, 168),
    maxSessions: loadIntegerPreference(STORAGE_NOVEL_MAX_SESSIONS, 1, 1, 9999),
    query: "",
    items: [],
  },
  rules: [],
  health: null,
  ui: {
    scanRunsCollapsed: loadCollapsedPreference(STORAGE_SCAN_RUNS_COLLAPSED, true),
    healthCollapsed: loadCollapsedPreference(STORAGE_HEALTH_COLLAPSED, true),
    rulesHelpCollapsed: loadCollapsedPreference(STORAGE_RULES_HELP_COLLAPSED, true),
  },
};

const elements = {
  healthBadge: document.getElementById("healthBadge"),
  healthOutput: document.getElementById("healthOutput"),
  refreshButton: document.getElementById("refreshButton"),
  forceScanButton: document.getElementById("forceScanButton"),
  purgeButton: document.getElementById("purgeButton"),
  queryInput: document.getElementById("queryInput"),
  ruleInput: document.getElementById("ruleInput"),
  shortRepeatInput: document.getElementById("shortRepeatInput"),
  fromInput: document.getElementById("fromInput"),
  toInput: document.getElementById("toInput"),
  scanStatusInput: document.getElementById("scanStatusInput"),
  novelWindowInput: document.getElementById("novelWindowInput"),
  novelMaxSessionsInput: document.getElementById("novelMaxSessionsInput"),
  novelQueryInput: document.getElementById("novelQueryInput"),
  novelRefreshButton: document.getElementById("novelRefreshButton"),
  novelClearAllButton: document.getElementById("novelClearAllButton"),
  novelBody: document.getElementById("novelBody"),
  networksBody: document.getElementById("networksBody"),
  networksPrevButton: document.getElementById("networksPrevButton"),
  networksNextButton: document.getElementById("networksNextButton"),
  networksPageLabel: document.getElementById("networksPageLabel"),
  runsBody: document.getElementById("runsBody"),
  runsPrevButton: document.getElementById("runsPrevButton"),
  runsNextButton: document.getElementById("runsNextButton"),
  runsPageLabel: document.getElementById("runsPageLabel"),
  toggleRunsButton: document.getElementById("toggleRunsButton"),
  runsContent: document.getElementById("runsContent"),
  kpiVisible: document.getElementById("kpiVisible"),
  kpiLastScan: document.getElementById("kpiLastScan"),
  kpiRules: document.getElementById("kpiRules"),
  kpiError: document.getElementById("kpiError"),
  toggleHealthButton: document.getElementById("toggleHealthButton"),
  healthContent: document.getElementById("healthContent"),
  ruleForm: document.getElementById("ruleForm"),
  rulesBody: document.getElementById("rulesBody"),
  toggleRulesHelpButton: document.getElementById("toggleRulesHelpButton"),
  rulesHelpContent: document.getElementById("rulesHelpContent"),
  runDrawer: document.getElementById("runDrawer"),
  runDrawerTitle: document.getElementById("runDrawerTitle"),
  runDrawerClose: document.getElementById("runDrawerClose"),
  runDetailOutput: document.getElementById("runDetailOutput"),
  runObservationsBody: document.getElementById("runObservationsBody"),
  toast: document.getElementById("toast"),
};

function showToast(text) {
  elements.toast.textContent = text;
  elements.toast.classList.remove("hidden");
  window.setTimeout(() => elements.toast.classList.add("hidden"), 2200);
}

function endpoint(path) {
  const base = API_BASE.endsWith("/") ? API_BASE.slice(0, -1) : API_BASE;
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return `${base}${suffix}`;
}

async function requestJson(path, init) {
  const response = await fetch(endpoint(path), init);
  if (!response.ok) {
    const raw = await response.text();
    throw new Error(`${response.status} ${raw}`);
  }
  return response.json();
}

function toIso(value) {
  if (!value) {
    return "";
  }
  return new Date(value).toISOString();
}

function toQuery(params) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") {
      return;
    }
    query.set(key, String(value));
  });
  return query.toString();
}

function formatDate(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function formatDuration(ms) {
  if (ms === null || ms === undefined) {
    return "-";
  }
  if (ms < 1000) {
    return `${ms} ms`;
  }
  return `${(ms / 1000).toFixed(2)} s`;
}

function normalizeWindowHours(value) {
  const parsed = Math.trunc(Number(value));
  if (!Number.isFinite(parsed)) {
    return state.novel.windowHours;
  }
  return Math.min(Math.max(parsed, 1), 168);
}

function updateNovelWindowPreference(nextValue) {
  const windowHours = normalizeWindowHours(nextValue);
  state.novel.windowHours = windowHours;
  elements.novelWindowInput.value = String(windowHours);
  try {
    window.localStorage.setItem(STORAGE_NOVEL_WINDOW_HOURS, String(windowHours));
  } catch (_error) {
    // Ignore storage write failures.
  }
}

function normalizeNovelMaxSessions(value) {
  const parsed = Math.trunc(Number(value));
  if (!Number.isFinite(parsed)) {
    return state.novel.maxSessions;
  }
  return Math.min(Math.max(parsed, 1), 9999);
}

function updateNovelMaxSessionsPreference(nextValue) {
  const maxSessions = normalizeNovelMaxSessions(nextValue);
  state.novel.maxSessions = maxSessions;
  elements.novelMaxSessionsInput.value = String(maxSessions);
  try {
    window.localStorage.setItem(STORAGE_NOVEL_MAX_SESSIONS, String(maxSessions));
  } catch (_error) {
    // Ignore storage write failures.
  }
}

function frequencyBandLabel(frequencyMhz, channel) {
  const frequency = Number(frequencyMhz || 0);
  if (Number.isFinite(frequency) && frequency >= 2400 && frequency <= 2500) {
    return "2.4 GHz";
  }
  if (Number.isFinite(frequency) && frequency >= 5000 && frequency <= 5900) {
    return "5 GHz";
  }
  if (Number.isFinite(frequency) && frequency >= 5925 && frequency <= 7125) {
    return "6 GHz";
  }

  const channelNumber = Number(channel || 0);
  if (Number.isFinite(channelNumber) && channelNumber >= 1 && channelNumber <= 14) {
    return "2.4 GHz";
  }
  if (Number.isFinite(channelNumber) && channelNumber >= 32 && channelNumber <= 177) {
    return "5 GHz";
  }
  if (Number.isFinite(channelNumber) && channelNumber > 177 && channelNumber <= 233) {
    return "6 GHz";
  }
  return "Unknown";
}

function applyCollapseState() {
  const runsExpanded = !state.ui.scanRunsCollapsed;
  elements.runsContent.hidden = state.ui.scanRunsCollapsed;
  elements.toggleRunsButton.setAttribute("aria-expanded", String(runsExpanded));
  elements.toggleRunsButton.textContent = runsExpanded ? "Hide" : "Show";

  const healthExpanded = !state.ui.healthCollapsed;
  elements.healthContent.hidden = state.ui.healthCollapsed;
  elements.toggleHealthButton.setAttribute("aria-expanded", String(healthExpanded));
  elements.toggleHealthButton.textContent = healthExpanded ? "Hide" : "Show";

  const rulesHelpExpanded = !state.ui.rulesHelpCollapsed;
  elements.rulesHelpContent.hidden = state.ui.rulesHelpCollapsed;
  elements.toggleRulesHelpButton.setAttribute("aria-expanded", String(rulesHelpExpanded));
  elements.toggleRulesHelpButton.textContent = rulesHelpExpanded ? "Hide help" : "Show help";
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function sortNetworks(items) {
  const key = state.networks.sortKey;
  const direction = state.networks.sortDirection === "asc" ? 1 : -1;

  return [...items].sort((left, right) => {
    const a = left[key] ?? "";
    const b = right[key] ?? "";
    if (typeof a === "number" && typeof b === "number") {
      return (a - b) * direction;
    }
    return String(a).localeCompare(String(b)) * direction;
  });
}

function renderHealth() {
  const health = state.health || {};
  const ok = Boolean(health.ok);
  elements.healthBadge.textContent = ok ? "Healthy" : "Error";
  elements.healthBadge.classList.remove("badge-neutral", "badge-ok", "badge-error");
  elements.healthBadge.classList.add(ok ? "badge-ok" : "badge-error");

  elements.kpiVisible.textContent = String(health.currently_visible ?? 0);
  elements.kpiLastScan.textContent = formatDate(health.last_scan_finished_at);
  elements.kpiRules.textContent = String(state.rules.length);
  elements.kpiError.textContent = health.last_error ? String(health.last_error) : "none";
  elements.healthOutput.textContent = JSON.stringify(health, null, 2);
}

function renderNetworks() {
  const rows = sortNetworks(state.networks.items);
  elements.networksBody.innerHTML = "";

  if (rows.length === 0) {
    elements.networksBody.innerHTML = '<tr><td colspan="8">No networks found.</td></tr>';
  }

  rows.forEach((item) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${item.currently_visible ? "yes" : "no"}</td>
      <td>${escapeHtml(item.ssid || "<hidden>")}</td>
      <td><code>${escapeHtml(item.bssid)}</code></td>
      <td>${item.seen_count}</td>
      <td>${item.strongest_rssi}</td>
      <td>${item.channel ?? "-"}</td>
      <td>${frequencyBandLabel(item.frequency_mhz, item.channel)}</td>
      <td>${formatDate(item.last_seen)}</td>
    `;
    elements.networksBody.appendChild(row);
  });

  const currentPage = Math.floor(state.networks.offset / state.networks.limit) + 1;
  elements.networksPageLabel.textContent = `Page ${currentPage}`;
  elements.networksPrevButton.disabled = state.networks.offset === 0;
  elements.networksNextButton.disabled = state.networks.items.length < state.networks.limit;
}

function renderNovelNetworks() {
  elements.novelBody.innerHTML = "";
  if (state.novel.items.length === 0) {
    elements.novelBody.innerHTML = '<tr><td colspan="9">No rare networks found.</td></tr>';
    return;
  }

  state.novel.items.forEach((item) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${escapeHtml(item.ssid || "<hidden>")}</td>
      <td><code>${escapeHtml(item.bssid)}</code></td>
      <td>${formatDate(item.first_seen)}</td>
      <td>${formatDate(item.last_seen)}</td>
      <td>${item.strongest_rssi ?? "-"}</td>
      <td>${item.channel ?? "-"}</td>
      <td>${frequencyBandLabel(item.frequency_mhz, item.channel)}</td>
      <td>${item.currently_visible ? "yes" : "no"}</td>
      <td class="table-action-cell"></td>
    `;
    const actionCell = row.querySelector(".table-action-cell");
    const clearButton = document.createElement("button");
    clearButton.type = "button";
    clearButton.className = "ghost";
    clearButton.textContent = "Clear";
    clearButton.addEventListener("click", async () => {
      try {
        await clearNovelNetwork(item.bssid);
      } catch (error) {
        showToast(error.message);
      }
    });
    actionCell?.appendChild(clearButton);
    elements.novelBody.appendChild(row);
  });
}

function renderRuns() {
  elements.runsBody.innerHTML = "";
  if (state.runs.items.length === 0) {
    elements.runsBody.innerHTML = '<tr><td colspan="9">No scan runs found.</td></tr>';
  }

  state.runs.items.forEach((run) => {
    const row = document.createElement("tr");
    row.classList.add("row-clickable");
    row.innerHTML = `
      <td>${run.id}</td>
      <td class="status-${escapeHtml(run.status)}">${escapeHtml(run.status)}</td>
      <td>${formatDate(run.started_at)}</td>
      <td>${formatDuration(run.duration_ms)}</td>
      <td>${run.seen_total}</td>
      <td>${run.new_count}</td>
      <td>${run.disappeared_count}</td>
      <td>${run.rule_matches}</td>
      <td>${escapeHtml(run.trigger || "-")}</td>
    `;
    row.addEventListener("click", () => openRunDetail(run.id));
    elements.runsBody.appendChild(row);
  });

  const currentPage = Math.floor(state.runs.offset / state.runs.limit) + 1;
  elements.runsPageLabel.textContent = `Page ${currentPage}`;
  elements.runsPrevButton.disabled = state.runs.offset === 0;
  elements.runsNextButton.disabled = state.runs.items.length < state.runs.limit;
}

function renderRules() {
  elements.rulesBody.innerHTML = "";
  if (state.rules.length === 0) {
    elements.rulesBody.innerHTML = '<tr><td colspan="8">No rules configured.</td></tr>';
  }

  state.rules.forEach((rule) => {
    const row = document.createElement("tr");
    const actions = document.createElement("td");

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.textContent = rule.enabled ? "Disable" : "Enable";
    toggle.addEventListener("click", async () => {
      await requestJson(`/rules/${rule.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !rule.enabled }),
      });
      await loadRules();
      renderRules();
      showToast("Rule updated");
    });

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger";
    remove.textContent = "Delete";
    remove.addEventListener("click", async () => {
      await requestJson(`/rules/${rule.id}`, { method: "DELETE" });
      await loadRules();
      renderRules();
      showToast("Rule deleted");
    });

    actions.appendChild(toggle);
    actions.append(" ");
    actions.appendChild(remove);

    row.innerHTML = `
      <td>${rule.id}</td>
      <td>${escapeHtml(rule.name)}</td>
      <td>${rule.enabled ? "yes" : "no"}</td>
      <td>${escapeHtml(rule.ssid_regex || "")}</td>
      <td>${escapeHtml(rule.bssid_prefix_csv || "")}</td>
      <td>${rule.min_rssi ?? ""}</td>
      <td>${rule.cooldown_sec}</td>
    `;

    row.appendChild(actions);
    elements.rulesBody.appendChild(row);
  });
}

async function loadHealth() {
  state.health = await requestJson("/health");
}

async function loadRules() {
  const payload = await requestJson("/rules");
  state.rules = Array.isArray(payload.items) ? payload.items : [];
}

function currentNetworkQuery() {
  return {
    query: elements.queryInput.value.trim(),
    rule: elements.ruleInput.value.trim(),
    short_repeat: elements.shortRepeatInput.value,
    from: toIso(elements.fromInput.value),
    to: toIso(elements.toInput.value),
    limit: state.networks.limit,
    offset: state.networks.offset,
  };
}

function currentRunsQuery() {
  return {
    status: elements.scanStatusInput.value,
    from: toIso(elements.fromInput.value),
    to: toIso(elements.toInput.value),
    limit: state.runs.limit,
    offset: state.runs.offset,
  };
}

function currentNovelQuery() {
  return {
    window_hours: state.novel.windowHours,
    max_sessions: state.novel.maxSessions,
    query: state.novel.query,
    limit: state.novel.limit,
    offset: state.novel.offset,
  };
}

async function loadNetworks() {
  const payload = await requestJson(`/networks?${toQuery(currentNetworkQuery())}`);
  state.networks.items = Array.isArray(payload.items) ? payload.items : [];
}

async function loadRuns() {
  const payload = await requestJson(`/scan-runs?${toQuery(currentRunsQuery())}`);
  state.runs.items = Array.isArray(payload.items) ? payload.items : [];
}

async function loadNovelNetworks() {
  const payload = await requestJson(`/novel-networks?${toQuery(currentNovelQuery())}`);
  state.novel.items = Array.isArray(payload.items) ? payload.items : [];
}

async function clearNovelNetwork(bssid) {
  await requestJson("/novel-networks/clear", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ bssid }),
  });
  await loadNovelNetworks();
  renderNovelNetworks();
  showToast(`Cleared ${bssid}`);
}

async function clearAllNovelNetworks() {
  const result = await requestJson("/novel-networks/clear", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      clear_all: true,
      window_hours: state.novel.windowHours,
      max_sessions: state.novel.maxSessions,
      query: state.novel.query,
    }),
  });
  await loadNovelNetworks();
  renderNovelNetworks();
  showToast(`Cleared ${result.cleared ?? 0} networks`);
}

async function openRunDetail(scanRunId) {
  const [run, observations] = await Promise.all([
    requestJson(`/scan-runs/${scanRunId}`),
    requestJson(`/scan-runs/${scanRunId}/observations?limit=120&offset=0`),
  ]);

  elements.runDrawerTitle.textContent = `Scan Run #${scanRunId}`;
  elements.runDetailOutput.textContent = JSON.stringify(run, null, 2);
  elements.runObservationsBody.innerHTML = "";

  const rows = Array.isArray(observations.items) ? observations.items : [];
  if (rows.length === 0) {
    const emptyMessage = run.raw_observations_available === false
      ? "Raw observations expired"
      : "No observations";
    elements.runObservationsBody.innerHTML = `<tr><td colspan="6">${escapeHtml(emptyMessage)}</td></tr>`;
  }

  rows.forEach((item) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${escapeHtml(item.ssid || "<hidden>")}</td>
      <td><code>${escapeHtml(item.bssid)}</code></td>
      <td>${item.rssi}</td>
      <td>${item.channel}</td>
      <td>${frequencyBandLabel(item.frequency_mhz, item.channel)}</td>
      <td>${formatDate(item.seen_at)}</td>
    `;
    elements.runObservationsBody.appendChild(row);
  });

  elements.runDrawer.classList.remove("hidden");
  elements.runDrawer.setAttribute("aria-hidden", "false");
}

function closeRunDrawer() {
  elements.runDrawer.classList.add("hidden");
  elements.runDrawer.setAttribute("aria-hidden", "true");
}

async function refreshAll() {
  await Promise.all([loadHealth(), loadRules(), loadNetworks(), loadRuns(), loadNovelNetworks()]);
  renderHealth();
  renderNetworks();
  renderNovelNetworks();
  renderRuns();
  renderRules();
}

function bindEvents() {
  elements.novelWindowInput.value = String(state.novel.windowHours);
  elements.novelMaxSessionsInput.value = String(state.novel.maxSessions);
  elements.novelQueryInput.value = state.novel.query;

  elements.toggleRunsButton.addEventListener("click", () => {
    state.ui.scanRunsCollapsed = !state.ui.scanRunsCollapsed;
    saveCollapsedPreference(STORAGE_SCAN_RUNS_COLLAPSED, state.ui.scanRunsCollapsed);
    applyCollapseState();
  });

  elements.toggleHealthButton.addEventListener("click", () => {
    state.ui.healthCollapsed = !state.ui.healthCollapsed;
    saveCollapsedPreference(STORAGE_HEALTH_COLLAPSED, state.ui.healthCollapsed);
    applyCollapseState();
  });

  elements.toggleRulesHelpButton.addEventListener("click", () => {
    state.ui.rulesHelpCollapsed = !state.ui.rulesHelpCollapsed;
    saveCollapsedPreference(STORAGE_RULES_HELP_COLLAPSED, state.ui.rulesHelpCollapsed);
    applyCollapseState();
  });

  elements.refreshButton.addEventListener("click", () => {
    refreshAll().catch((error) => showToast(error.message));
  });

  elements.novelRefreshButton.addEventListener("click", async () => {
    state.novel.query = elements.novelQueryInput.value.trim();
    updateNovelWindowPreference(elements.novelWindowInput.value);
    updateNovelMaxSessionsPreference(elements.novelMaxSessionsInput.value);
    state.novel.offset = 0;
    await loadNovelNetworks();
    renderNovelNetworks();
  });

  elements.novelClearAllButton.addEventListener("click", async () => {
    if (!window.confirm("Clear all currently listed rare networks?")) {
      return;
    }
    await clearAllNovelNetworks();
  });

  elements.forceScanButton.addEventListener("click", async () => {
    await requestJson("/scan/trigger", { method: "POST" });
    showToast("Force scan triggered");
    await refreshAll();
  });

  elements.purgeButton.addEventListener("click", async () => {
    await requestJson("/history/purge", { method: "POST" });
    showToast("History purge started");
    await refreshAll();
  });

  [
    elements.queryInput,
    elements.ruleInput,
    elements.shortRepeatInput,
    elements.fromInput,
    elements.toInput,
    elements.scanStatusInput,
  ].forEach((input) => {
    input.addEventListener("change", () => {
      state.networks.offset = 0;
      state.runs.offset = 0;
      refreshAll().catch((error) => showToast(error.message));
    });
  });

  elements.novelWindowInput.addEventListener("change", () => {
    updateNovelWindowPreference(elements.novelWindowInput.value);
    state.novel.offset = 0;
    loadNovelNetworks()
      .then(() => renderNovelNetworks())
      .catch((error) => showToast(error.message));
  });

  elements.novelMaxSessionsInput.addEventListener("change", () => {
    updateNovelMaxSessionsPreference(elements.novelMaxSessionsInput.value);
    state.novel.offset = 0;
    loadNovelNetworks()
      .then(() => renderNovelNetworks())
      .catch((error) => showToast(error.message));
  });

  elements.novelQueryInput.addEventListener("change", () => {
    state.novel.query = elements.novelQueryInput.value.trim();
    state.novel.offset = 0;
    loadNovelNetworks()
      .then(() => renderNovelNetworks())
      .catch((error) => showToast(error.message));
  });

  elements.novelQueryInput.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") {
      return;
    }
    event.preventDefault();
    state.novel.query = elements.novelQueryInput.value.trim();
    state.novel.offset = 0;
    loadNovelNetworks()
      .then(() => renderNovelNetworks())
      .catch((error) => showToast(error.message));
  });

  elements.networksPrevButton.addEventListener("click", () => {
    state.networks.offset = Math.max(0, state.networks.offset - state.networks.limit);
    refreshAll().catch((error) => showToast(error.message));
  });

  elements.networksNextButton.addEventListener("click", () => {
    state.networks.offset += state.networks.limit;
    refreshAll().catch((error) => showToast(error.message));
  });

  elements.runsPrevButton.addEventListener("click", () => {
    state.runs.offset = Math.max(0, state.runs.offset - state.runs.limit);
    refreshAll().catch((error) => showToast(error.message));
  });

  elements.runsNextButton.addEventListener("click", () => {
    state.runs.offset += state.runs.limit;
    refreshAll().catch((error) => showToast(error.message));
  });

  document.querySelectorAll("th[data-sort]").forEach((header) => {
    header.addEventListener("click", () => {
      const key = header.getAttribute("data-sort");
      if (!key) {
        return;
      }
      if (state.networks.sortKey === key) {
        state.networks.sortDirection = state.networks.sortDirection === "asc" ? "desc" : "asc";
      } else {
        state.networks.sortKey = key;
        state.networks.sortDirection = "asc";
      }
      renderNetworks();
    });
  });

  elements.ruleForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(elements.ruleForm);
    const payload = {
      name: String(formData.get("name") || "").trim(),
      enabled: true,
      ssid_regex: String(formData.get("ssid_regex") || "").trim() || null,
      bssid_prefix_csv: String(formData.get("bssid_prefix_csv") || "").trim() || null,
      min_rssi: formData.get("min_rssi") ? Number(formData.get("min_rssi")) : null,
      cooldown_sec: Number(formData.get("cooldown_sec") || 0),
    };
    await requestJson("/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    elements.ruleForm.reset();
    showToast("Rule created");
    await refreshAll();
  });

  elements.runDrawerClose.addEventListener("click", closeRunDrawer);
}

bindEvents();
applyCollapseState();
refreshAll().catch((error) => {
  showToast(error.message);
  elements.healthOutput.textContent = error.message;
});
