const healthOutput = document.getElementById("healthOutput");
const networksBody = document.getElementById("networksBody");
const rulesBody = document.getElementById("rulesBody");
const refreshButton = document.getElementById("refreshButton");
const ruleForm = document.getElementById("ruleForm");

const queryInput = document.getElementById("queryInput");
const ruleInput = document.getElementById("ruleInput");
const shortRepeatInput = document.getElementById("shortRepeatInput");
const limitInput = document.getElementById("limitInput");

function toQuery(params) {
  const sp = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") {
      return;
    }
    sp.set(key, String(value));
  });
  return sp.toString();
}

async function getJson(path, init) {
  const res = await fetch(path, init);
  if (!res.ok) {
    const raw = await res.text();
    throw new Error(`${res.status} ${raw}`);
  }
  return res.json();
}

function renderHealth(data) {
  healthOutput.textContent = JSON.stringify(data, null, 2);
}

function renderNetworks(items) {
  networksBody.innerHTML = "";
  items.forEach((item) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${item.currently_visible ? "yes" : "no"}</td>
      <td>${item.ssid || "<hidden>"}</td>
      <td><code>${item.bssid}</code></td>
      <td>${item.seen_count}</td>
      <td>${item.strongest_rssi}</td>
      <td>${item.last_seen}</td>
    `;
    networksBody.appendChild(tr);
  });
}

function renderRules(items) {
  rulesBody.innerHTML = "";
  items.forEach((item) => {
    const tr = document.createElement("tr");
    const toggleButton = document.createElement("button");
    toggleButton.type = "button";
    toggleButton.textContent = item.enabled ? "Disable" : "Enable";
    toggleButton.addEventListener("click", async () => {
      await getJson(`/v1/rules/${item.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !item.enabled }),
      });
      await loadAll();
    });

    const deleteButton = document.createElement("button");
    deleteButton.type = "button";
    deleteButton.className = "danger";
    deleteButton.textContent = "Delete";
    deleteButton.addEventListener("click", async () => {
      await getJson(`/v1/rules/${item.id}`, { method: "DELETE" });
      await loadAll();
    });

    tr.innerHTML = `
      <td>${item.id}</td>
      <td>${item.name}</td>
      <td>${item.enabled ? "yes" : "no"}</td>
      <td>${item.ssid_regex || ""}</td>
      <td>${item.bssid_prefix_csv || ""}</td>
      <td>${item.min_rssi ?? ""}</td>
      <td>${item.cooldown_sec}</td>
      <td></td>
    `;
    tr.lastElementChild.appendChild(toggleButton);
    tr.lastElementChild.append(" ");
    tr.lastElementChild.appendChild(deleteButton);
    rulesBody.appendChild(tr);
  });
}

async function loadAll() {
  const params = {
    query: queryInput.value.trim(),
    rule: ruleInput.value.trim(),
    short_repeat: shortRepeatInput.value,
    limit: limitInput.value,
  };

  const [health, networks, rules] = await Promise.all([
    getJson("/v1/health"),
    getJson(`/v1/networks?${toQuery(params)}`),
    getJson("/v1/rules"),
  ]);

  renderHealth(health);
  renderNetworks(networks.items || []);
  renderRules(rules.items || []);
}

refreshButton.addEventListener("click", () => {
  loadAll().catch((error) => {
    healthOutput.textContent = error.message;
  });
});

[queryInput, ruleInput, shortRepeatInput, limitInput].forEach((element) => {
  element.addEventListener("change", () => {
    loadAll().catch((error) => {
      healthOutput.textContent = error.message;
    });
  });
});

ruleForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(ruleForm);
  const payload = {
    name: String(formData.get("name") || "").trim(),
    enabled: true,
    ssid_regex: String(formData.get("ssid_regex") || "").trim() || null,
    bssid_prefix_csv: String(formData.get("bssid_prefix_csv") || "").trim() || null,
    min_rssi: formData.get("min_rssi") ? Number(formData.get("min_rssi")) : null,
    cooldown_sec: Number(formData.get("cooldown_sec") || 0),
  };
  await getJson("/v1/rules", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  ruleForm.reset();
  await loadAll();
});

loadAll().catch((error) => {
  healthOutput.textContent = error.message;
});
