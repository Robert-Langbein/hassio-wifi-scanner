const STORAGE_SCAN_RUNS_COLLAPSED = "wps_scan_runs_collapsed";
const STORAGE_HEALTH_COLLAPSED = "wps_health_collapsed";
const STORAGE_RULES_HELP_COLLAPSED = "wps_rules_help_collapsed";
const STORAGE_NOVEL_WINDOW_HOURS = "wps_novel_window_hours";
const STORAGE_NOVEL_MAX_SESSIONS = "wps_novel_max_sessions";
const TOAST_DURATION_MS = 2800;
const THEME_VARIABLE_MAP = {
  "--primary-color": "--wps-color-primary",
  "--accent-color": "--wps-color-accent",
  "--primary-background-color": "--wps-bg",
  "--card-background-color": "--wps-surface-0",
  "--secondary-background-color": "--wps-surface-1",
  "--divider-color": "--wps-border",
  "--primary-text-color": "--wps-text",
  "--secondary-text-color": "--wps-muted",
  "--error-color": "--wps-color-error",
  "--success-color": "--wps-color-success",
  "--warning-color": "--wps-color-warning",
};

function trimTrailingSlashes(value) {
  if (!value) {
    return "";
  }
  return value.length > 1 ? value.replace(/\/+$/, "") : value;
}

function resolveRuntimeConfig() {
  const existingApiBase = trimTrailingSlashes(String(window.WPS_API_BASE || ""));
  const existingStaticBase = trimTrailingSlashes(String(window.WPS_STATIC_BASE || ""));
  if (existingApiBase || existingStaticBase) {
    const apiBase = existingApiBase || "/v1";
    const staticBase = existingStaticBase || "/ui";
    window.WPS_API_BASE = apiBase;
    window.WPS_STATIC_BASE = staticBase;
    return { apiBase, staticBase };
  }

  const pathname = window.location.pathname || "/";
  const normalizedPath = trimTrailingSlashes(pathname) || "/";
  if (normalizedPath === "/api/wifi_presence_scanner/panel") {
    window.WPS_API_BASE = "/api/wifi_presence_scanner";
    window.WPS_STATIC_BASE = "/api/wifi_presence_scanner_static";
    return {
      apiBase: window.WPS_API_BASE,
      staticBase: window.WPS_STATIC_BASE,
    };
  }

  let basePath = normalizedPath;
  if (basePath.endsWith("/index.html")) {
    basePath = basePath.slice(0, -"/index.html".length) || "/";
  }
  if (basePath === "/") {
    basePath = "";
  }

  window.WPS_API_BASE = `${basePath}/v1`;
  window.WPS_STATIC_BASE = `${basePath}/ui`;
  return {
    apiBase: window.WPS_API_BASE,
    staticBase: window.WPS_STATIC_BASE,
  };
}

const runtimeConfig = resolveRuntimeConfig();
const API_BASE = runtimeConfig.apiBase;

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
    pendingCount: 0,
    toastTimer: 0,
  },
};

const elements = {
  appShell: document.getElementById("appShell"),
  actionStatus: document.getElementById("actionStatus"),
  actionStatusText: document.getElementById("actionStatusText"),
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

function setStatus(text, { tone = "neutral", busy = false } = {}) {
  const message = String(text || "Ready.").trim() || "Ready.";
  elements.actionStatus.dataset.tone = tone;
  elements.actionStatus.dataset.busy = String(busy);
  elements.actionStatusText.textContent = message;
}

function showToast(text, { tone = "info" } = {}) {
  const message = String(text || "").trim();
  if (!message) {
    return;
  }

  if (state.ui.toastTimer) {
    window.clearTimeout(state.ui.toastTimer);
  }
  elements.toast.textContent = message;
  elements.toast.dataset.tone = tone;
  elements.toast.classList.remove("hidden");
  state.ui.toastTimer = window.setTimeout(() => {
    elements.toast.classList.add("hidden");
    elements.toast.dataset.tone = "info";
  }, TOAST_DURATION_MS);
}

function setDocumentBusy(isBusy) {
  document.body.dataset.busy = isBusy ? "true" : "false";
  if (elements.appShell) {
    elements.appShell.dataset.busy = String(isBusy);
  }
}

function beginBusy(message) {
  state.ui.pendingCount += 1;
  setDocumentBusy(true);
  setStatus(message, { tone: "loading", busy: true });
}

function endBusy() {
  state.ui.pendingCount = Math.max(0, state.ui.pendingCount - 1);
  if (state.ui.pendingCount === 0) {
    setDocumentBusy(false);
  }
}

function setButtonPending(button, pendingLabel) {
  if (!button) {
    return () => {};
  }

  const originalLabel = button.textContent;
  const originalDisabled = button.disabled;
  button.dataset.pending = "true";
  button.setAttribute("aria-busy", "true");
  button.disabled = true;
  if (pendingLabel) {
    button.textContent = pendingLabel;
  }

  return () => {
    button.disabled = originalDisabled;
    button.textContent = originalLabel;
    button.removeAttribute("aria-busy");
    delete button.dataset.pending;
  };
}

function applyHomeAssistantTheme() {
  const root = document.documentElement;
  let sourceElement = root;
  let linkedTheme = false;

  try {
    if (window.parent && window.parent !== window && window.parent.document?.documentElement) {
      sourceElement = window.parent.document.documentElement;
      linkedTheme = true;
    }
  } catch (_error) {
    sourceElement = root;
  }

  const computed = window.getComputedStyle(sourceElement);
  let applied = false;
  Object.entries(THEME_VARIABLE_MAP).forEach(([sourceName, targetName]) => {
    const value = computed.getPropertyValue(sourceName).trim();
    if (!value) {
      return;
    }
    root.style.setProperty(targetName, value);
    applied = true;
  });

  root.dataset.haTheme = applied ? (linkedTheme ? "linked" : "local") : "fallback";
}

function watchHomeAssistantTheme() {
  try {
    if (!window.parent || window.parent === window) {
      return;
    }
    const target = window.parent.document?.documentElement;
    if (!target) {
      return;
    }
    const observer = new MutationObserver(() => {
      window.requestAnimationFrame(applyHomeAssistantTheme);
    });
    observer.observe(target, {
      attributes: true,
      attributeFilter: ["class", "style"],
    });
    if (window.parent.document.body) {
      observer.observe(window.parent.document.body, {
        attributes: true,
        attributeFilter: ["class", "style"],
      });
    }
  } catch (_error) {
    // Ignore theme observation failures.
  }
}

function endpoint(path) {
  const base = API_BASE.endsWith("/") ? API_BASE.slice(0, -1) : API_BASE;
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return `${base}${suffix}`;
}

function extractErrorText(raw) {
  const text = String(raw || "").trim();
  if (!text) {
    return "";
  }
  if (!(text.startsWith("{") || text.startsWith("["))) {
    return text;
  }

  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      if (typeof parsed.error === "string") {
        return extractErrorText(parsed.error);
      }
      if (typeof parsed.message === "string") {
        return extractErrorText(parsed.message);
      }
    }
  } catch (_error) {
    return text;
  }
  return text;
}

function sentence(text) {
  const trimmed = String(text || "").trim();
  if (!trimmed) {
    return "Request failed.";
  }
  const normalized = trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  return /[.!?]$/.test(normalized) ? normalized : `${normalized}.`;
}

function normalizeErrorMessage(error) {
  let message = error instanceof Error ? error.message : String(error || "");
  message = message.trim();
  if (!message) {
    return "Request failed.";
  }

  const responseStatusMatch = message.match(/^\d+\s+(.+)$/);
  if (responseStatusMatch) {
    message = responseStatusMatch[1];
  }

  message = message.replace(/^Backend HTTP \d+:\s*/i, "");
  message = message.replace(/^Backend request failed:\s*/i, "");
  message = message.replace(/^Backend response parse failed:\s*/i, "");
  message = extractErrorText(message).replaceAll("'", "").trim();

  const knownErrors = {
    scan_in_progress: "A scan is already running.",
    quiet_window: "The current quiet window prevents a manual scan.",
    not_found: "The requested item no longer exists.",
    integration_not_loaded: "The Home Assistant integration is not loaded.",
    unauthorized: "Authentication with the scanner backend failed.",
    forbidden: "The request is not allowed.",
  };
  if (knownErrors[message]) {
    return knownErrors[message];
  }

  if (message.toLowerCase() === "failed to fetch") {
    return "Could not reach the scanner backend.";
  }
  if (message.toLowerCase() === "backend response is not an object") {
    return "The scanner backend returned an unexpected response.";
  }

  return sentence(message);
}

async function requestJson(path, init = {}) {
  try {
    const headers = new Headers(init.headers || {});
    if (!headers.has("Accept")) {
      headers.set("Accept", "application/json");
    }

    const response = await fetch(endpoint(path), {
      ...init,
      headers,
    });
    const raw = await response.text();
    let payload = {};

    if (raw) {
      try {
        payload = JSON.parse(raw);
      } catch (_error) {
        if (response.ok) {
          throw new Error("The scanner backend returned invalid JSON.");
        }
      }
    }

    if (!response.ok) {
      const source =
        payload && typeof payload === "object" && !Array.isArray(payload)
          ? payload.error || payload.message || raw
          : raw;
      throw new Error(normalizeErrorMessage(source || `${response.status} request failed`));
    }

    if (!raw) {
      return {};
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new Error("The scanner backend returned an unexpected response.");
    }
    return payload;
  } catch (error) {
    throw new Error(normalizeErrorMessage(error));
  }
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

function formatRefreshTime() {
  return new Date().toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
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
  elements.kpiRules.textContent = String(state.rules.length);

  if (!state.health) {
    elements.healthBadge.textContent = "Unknown";
    elements.healthBadge.classList.remove("badge-ok", "badge-error");
    elements.healthBadge.classList.add("badge-neutral");
    elements.kpiVisible.textContent = "-";
    elements.kpiLastScan.textContent = "-";
    elements.kpiError.textContent = "none";
    elements.healthOutput.textContent = "Loading...";
    return;
  }

  const health = state.health;
  const ok = Boolean(health.ok);
  elements.healthBadge.textContent = ok ? "Healthy" : "Needs Attention";
  elements.healthBadge.classList.remove("badge-neutral", "badge-ok", "badge-error");
  elements.healthBadge.classList.add(ok ? "badge-ok" : "badge-error");

  elements.kpiVisible.textContent = String(health.currently_visible ?? 0);
  elements.kpiLastScan.textContent = formatDate(health.last_scan_finished_at);
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

    const clearButton = document.createElement("button");
    clearButton.type = "button";
    clearButton.className = "ghost";
    clearButton.textContent = "Clear";
    clearButton.addEventListener("click", () => {
      void runRequest({
        button: clearButton,
        pendingLabel: "Clearing...",
        statusMessage: `Clearing rare network ${item.bssid}...`,
        task: async () => {
          const result = await requestJson("/novel-networks/clear", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ bssid: item.bssid }),
          });
          await loadNovelNetworks();
          renderNovelNetworks();
          return result;
        },
        successMessage: (result) => ({
          tone: "success",
          message: `Cleared rare network ${(result && result.bssid) || item.bssid}.`,
        }),
      });
    });

    row.querySelector(".table-action-cell")?.appendChild(clearButton);
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
    row.addEventListener("click", () => {
      void openRunDetail(run.id);
    });
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
    const actionsCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "table-action-group";

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = rule.enabled ? "ghost" : "";
    toggle.textContent = rule.enabled ? "Disable" : "Enable";
    toggle.addEventListener("click", () => {
      const nextEnabled = !rule.enabled;
      void runRequest({
        button: toggle,
        pendingLabel: nextEnabled ? "Enabling..." : "Disabling...",
        statusMessage: `${nextEnabled ? "Enabling" : "Disabling"} rule "${rule.name}"...`,
        task: async () => {
          await requestJson(`/rules/${rule.id}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enabled: nextEnabled }),
          });
          await loadRules();
          renderRules();
          renderHealth();
        },
        successMessage: {
          tone: "success",
          message: nextEnabled ? `Rule "${rule.name}" enabled.` : `Rule "${rule.name}" disabled.`,
        },
      });
    });

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger";
    remove.textContent = "Delete";
    remove.addEventListener("click", () => {
      void runRequest({
        button: remove,
        pendingLabel: "Deleting...",
        statusMessage: `Deleting rule "${rule.name}"...`,
        task: async () => {
          await requestJson(`/rules/${rule.id}`, { method: "DELETE" });
          await loadRules();
          renderRules();
          renderHealth();
        },
        successMessage: {
          tone: "success",
          message: `Rule "${rule.name}" deleted.`,
        },
      });
    });

    actions.appendChild(toggle);
    actions.appendChild(remove);
    actionsCell.appendChild(actions);

    row.innerHTML = `
      <td>${rule.id}</td>
      <td>${escapeHtml(rule.name)}</td>
      <td>${rule.enabled ? "yes" : "no"}</td>
      <td>${escapeHtml(rule.ssid_regex || "")}</td>
      <td>${escapeHtml(rule.bssid_prefix_csv || "")}</td>
      <td>${rule.min_rssi ?? ""}</td>
      <td>${rule.cooldown_sec}</td>
    `;

    row.appendChild(actionsCell);
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

async function loadAllData() {
  await Promise.all([loadHealth(), loadRules(), loadNetworks(), loadRuns(), loadNovelNetworks()]);
}

function renderAll() {
  renderHealth();
  renderNetworks();
  renderNovelNetworks();
  renderRuns();
  renderRules();
}

function resolveSuccessFeedback(details, fallbackTone = "success") {
  if (!details) {
    return null;
  }
  if (typeof details === "string") {
    return { tone: fallbackTone, message: details };
  }
  return {
    tone: details.tone || fallbackTone,
    message: String(details.message || "").trim(),
  };
}

async function runRequest({
  button = null,
  pendingLabel = "",
  statusMessage = "Working...",
  task,
  successMessage = null,
  toastOnSuccess = true,
  statusAfterSuccess = null,
}) {
  if (button?.dataset.pending === "true") {
    return null;
  }

  const restoreButton = setButtonPending(button, pendingLabel);
  beginBusy(statusMessage);

  try {
    const result = await task();
    const success =
      resolveSuccessFeedback(
        typeof successMessage === "function" ? successMessage(result) : successMessage,
      ) ||
      (statusAfterSuccess
        ? {
            tone: "neutral",
            message:
              typeof statusAfterSuccess === "function"
                ? statusAfterSuccess(result)
                : statusAfterSuccess,
          }
        : null);

    if (success?.message) {
      setStatus(success.message, { tone: success.tone, busy: false });
      if (toastOnSuccess) {
        showToast(success.message, { tone: success.tone });
      }
    } else {
      setStatus("Ready.", { tone: "neutral", busy: false });
    }
    return result;
  } catch (error) {
    const message = normalizeErrorMessage(error);
    setStatus(message, { tone: "error", busy: false });
    showToast(message, { tone: "error" });
    return null;
  } finally {
    endBusy();
    restoreButton();
  }
}

function describeForceScanResult(result) {
  if (!result || typeof result !== "object") {
    return {
      tone: "success",
      message: "Manual scan request sent.",
    };
  }

  if (result.status === "ok") {
    return {
      tone: "success",
      message: `Manual scan finished: ${result.seen ?? 0} seen, ${result.new_count ?? 0} new, ${result.disappeared_count ?? 0} gone.`,
    };
  }

  if (result.status === "skipped") {
    if (result.reason === "scan_in_progress") {
      return {
        tone: "warning",
        message: "Manual scan skipped because another scan is already running.",
      };
    }
    if (result.reason === "quiet_window") {
      return {
        tone: "warning",
        message: "Manual scan skipped because the quiet window is active.",
      };
    }
    return {
      tone: "warning",
      message: "Manual scan was skipped.",
    };
  }

  if (result.status === "error") {
    return {
      tone: "error",
      message: normalizeErrorMessage(result.error || "Manual scan failed"),
    };
  }

  return {
    tone: "success",
    message: "Manual scan request completed.",
  };
}

function describePurgeResult(result) {
  const totalDeleted = Object.values(result || {}).reduce((sum, value) => {
    const count = Number(value);
    return Number.isFinite(count) ? sum + count : sum;
  }, 0);
  if (totalDeleted <= 0) {
    return {
      tone: "warning",
      message: "No history records needed purging.",
    };
  }
  return {
    tone: "success",
    message: `Purged ${totalDeleted} history records.`,
  };
}

async function refreshAll({
  button = null,
  pendingLabel = "",
  statusMessage = "Refreshing scanner data...",
} = {}) {
  const result = await runRequest({
    button,
    pendingLabel,
    statusMessage,
    task: async () => {
      await loadAllData();
      renderAll();
    },
    toastOnSuccess: false,
    statusAfterSuccess: `Updated ${formatRefreshTime()}.`,
  });

  if (result === null && !state.health) {
    elements.healthOutput.textContent = "Unable to load scanner data.";
  }
  return result;
}

async function refreshNovelNetworksView({
  button = null,
  pendingLabel = "",
  statusMessage = "Refreshing rare networks...",
} = {}) {
  return runRequest({
    button,
    pendingLabel,
    statusMessage,
    task: async () => {
      await loadNovelNetworks();
      renderNovelNetworks();
    },
    toastOnSuccess: false,
    statusAfterSuccess: `Rare networks updated ${formatRefreshTime()}.`,
  });
}

async function openRunDetail(scanRunId) {
  return runRequest({
    statusMessage: `Loading scan run #${scanRunId}...`,
    task: async () => {
      const [run, observations] = await Promise.all([
        requestJson(`/scan-runs/${scanRunId}`),
        requestJson(`/scan-runs/${scanRunId}/observations?limit=120&offset=0`),
      ]);

      elements.runDrawerTitle.textContent = `Scan Run #${scanRunId}`;
      elements.runDetailOutput.textContent = JSON.stringify(run, null, 2);
      elements.runObservationsBody.innerHTML = "";

      const rows = Array.isArray(observations.items) ? observations.items : [];
      if (rows.length === 0) {
        const emptyMessage =
          run.raw_observations_available === false ? "Raw observations expired" : "No observations";
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
    },
    toastOnSuccess: false,
    statusAfterSuccess: `Loaded scan run #${scanRunId}.`,
  });
}

function closeRunDrawer() {
  elements.runDrawer.classList.add("hidden");
  elements.runDrawer.setAttribute("aria-hidden", "true");
  setStatus(`Updated ${formatRefreshTime()}.`, { tone: "neutral", busy: false });
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
    void refreshAll({
      button: elements.refreshButton,
      pendingLabel: "Refreshing...",
      statusMessage: "Refreshing scanner data...",
    });
  });

  elements.novelRefreshButton.addEventListener("click", () => {
    state.novel.query = elements.novelQueryInput.value.trim();
    updateNovelWindowPreference(elements.novelWindowInput.value);
    updateNovelMaxSessionsPreference(elements.novelMaxSessionsInput.value);
    state.novel.offset = 0;
    void refreshNovelNetworksView({
      button: elements.novelRefreshButton,
      pendingLabel: "Refreshing...",
      statusMessage: "Refreshing rare networks...",
    });
  });

  elements.novelClearAllButton.addEventListener("click", () => {
    if (!window.confirm("Clear all currently listed rare networks?")) {
      return;
    }
    void runRequest({
      button: elements.novelClearAllButton,
      pendingLabel: "Clearing...",
      statusMessage: "Clearing rare networks...",
      task: async () => {
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
        return result;
      },
      successMessage: (result) => ({
        tone: "success",
        message: `Cleared ${result?.cleared ?? 0} rare networks.`,
      }),
    });
  });

  elements.forceScanButton.addEventListener("click", () => {
    void runRequest({
      button: elements.forceScanButton,
      pendingLabel: "Scanning...",
      statusMessage: "Running a manual scan...",
      task: async () => {
        const result = await requestJson("/scan/trigger", { method: "POST" });
        await loadAllData();
        renderAll();
        return result;
      },
      successMessage: describeForceScanResult,
    });
  });

  elements.purgeButton.addEventListener("click", () => {
    void runRequest({
      button: elements.purgeButton,
      pendingLabel: "Purging...",
      statusMessage: "Purging historical scanner data...",
      task: async () => {
        const result = await requestJson("/history/purge", { method: "POST" });
        await loadAllData();
        renderAll();
        return result;
      },
      successMessage: describePurgeResult,
    });
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
      void refreshAll({
        statusMessage: "Applying filters...",
      });
    });
  });

  elements.novelWindowInput.addEventListener("change", () => {
    updateNovelWindowPreference(elements.novelWindowInput.value);
    state.novel.offset = 0;
    void refreshNovelNetworksView({
      statusMessage: "Applying rare network filters...",
    });
  });

  elements.novelMaxSessionsInput.addEventListener("change", () => {
    updateNovelMaxSessionsPreference(elements.novelMaxSessionsInput.value);
    state.novel.offset = 0;
    void refreshNovelNetworksView({
      statusMessage: "Applying rare network filters...",
    });
  });

  elements.novelQueryInput.addEventListener("change", () => {
    state.novel.query = elements.novelQueryInput.value.trim();
    state.novel.offset = 0;
    void refreshNovelNetworksView({
      statusMessage: "Applying rare network filters...",
    });
  });

  elements.novelQueryInput.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") {
      return;
    }
    event.preventDefault();
    state.novel.query = elements.novelQueryInput.value.trim();
    state.novel.offset = 0;
    void refreshNovelNetworksView({
      statusMessage: "Applying rare network filters...",
    });
  });

  elements.networksPrevButton.addEventListener("click", () => {
    state.networks.offset = Math.max(0, state.networks.offset - state.networks.limit);
    void refreshAll({
      button: elements.networksPrevButton,
      pendingLabel: "Loading...",
      statusMessage: "Loading previous networks page...",
    });
  });

  elements.networksNextButton.addEventListener("click", () => {
    state.networks.offset += state.networks.limit;
    void refreshAll({
      button: elements.networksNextButton,
      pendingLabel: "Loading...",
      statusMessage: "Loading next networks page...",
    });
  });

  elements.runsPrevButton.addEventListener("click", () => {
    state.runs.offset = Math.max(0, state.runs.offset - state.runs.limit);
    void refreshAll({
      button: elements.runsPrevButton,
      pendingLabel: "Loading...",
      statusMessage: "Loading previous scan runs...",
    });
  });

  elements.runsNextButton.addEventListener("click", () => {
    state.runs.offset += state.runs.limit;
    void refreshAll({
      button: elements.runsNextButton,
      pendingLabel: "Loading...",
      statusMessage: "Loading next scan runs...",
    });
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
      setStatus(`Sorted networks by ${key.replaceAll("_", " ")}.`, { tone: "neutral", busy: false });
    });
  });

  elements.ruleForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const submitButton = elements.ruleForm.querySelector('button[type="submit"]');
    void runRequest({
      button: submitButton,
      pendingLabel: "Creating...",
      statusMessage: "Creating a new rule...",
      task: async () => {
        const formData = new FormData(elements.ruleForm);
        const payload = {
          name: String(formData.get("name") || "").trim(),
          enabled: true,
          ssid_regex: String(formData.get("ssid_regex") || "").trim() || null,
          bssid_prefix_csv: String(formData.get("bssid_prefix_csv") || "").trim() || null,
          min_rssi: formData.get("min_rssi") ? Number(formData.get("min_rssi")) : null,
          cooldown_sec: Number(formData.get("cooldown_sec") || 0),
        };
        const result = await requestJson("/rules", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        elements.ruleForm.reset();
        await loadRules();
        renderRules();
        renderHealth();
        return result;
      },
      successMessage: (result) => ({
        tone: "success",
        message: `Rule "${result?.name || "new rule"}" created.`,
      }),
    });
  });

  elements.runDrawerClose.addEventListener("click", closeRunDrawer);
}

applyHomeAssistantTheme();
watchHomeAssistantTheme();
bindEvents();
applyCollapseState();
renderHealth();
setStatus("Loading scanner data...", { tone: "loading", busy: true });
void refreshAll({
  statusMessage: "Loading scanner data...",
});
