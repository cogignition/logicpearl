const data = await loadJson("./cases.json");
const state = {
  selectedCaseId: data.cases[0]?.id || null
};

render();

async function loadJson(path) {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`Unable to load demo data: ${path}`);
  }
  return response.json();
}

function render() {
  renderHero();
  renderNav();
  renderArtifacts();
  renderPrinciples();
  renderCase();
}

function renderHero() {
  setText("demo-title", data.title);
  setText("demo-subtitle", data.subtitle);
  setText("demo-tagline", data.tagline);
  const grid = document.getElementById("stats-grid");
  grid.replaceChildren(...data.metrics.map(renderMetricCard));
}

function renderMetricCard(metric) {
  const card = document.createElement("article");
  card.className = "metric-card";
  card.innerHTML = `
    <div class="meta-label">${escapeHtml(metric.label)}</div>
    <div class="metric-value">${escapeHtml(metric.value)}</div>
    <div class="metric-note">${escapeHtml(metric.note || "")}</div>
  `;
  return card;
}

function renderNav() {
  const nav = document.getElementById("case-nav");
  nav.replaceChildren(...data.cases.map((demoCase) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `case-button${demoCase.id === state.selectedCaseId ? " active" : ""}`;
    button.innerHTML = `
      <div class="case-button-title">${escapeHtml(demoCase.title)}</div>
      <div class="case-button-note">${escapeHtml(demoCase.route_status.replaceAll("_", " "))}</div>
    `;
    button.addEventListener("click", () => {
      state.selectedCaseId = demoCase.id;
      renderNav();
      renderCase();
    });
    return button;
  }));
}

function renderArtifacts() {
  const host = document.getElementById("artifact-grid");
  host.replaceChildren(...data.artifacts.map((artifact) => {
    const card = document.createElement("article");
    card.className = "artifact-card";
    card.innerHTML = `
      <div class="meta-label">Artifact</div>
      <h3>${escapeHtml(artifact.label)}</h3>
      <p>${escapeHtml(artifact.description || "")}</p>
      <a href="${escapeAttribute(artifact.path)}">Open artifact</a>
      <div class="metric-note">${escapeHtml(artifact.path)}</div>
    `;
    return card;
  }));
}

function renderPrinciples() {
  const host = document.getElementById("principles");
  host.replaceChildren(...data.principles.map((principle) => {
    const item = document.createElement("li");
    item.textContent = principle;
    return item;
  }));
}

function renderCase() {
  const demoCase = data.cases.find((entry) => entry.id === state.selectedCaseId) || data.cases[0];
  setText("case-title", demoCase.title);
  setText("case-summary", demoCase.summary);
  setText("risk-score", demoCase.observer.risk_score.toFixed(2));
  setText("verdict-title", humanizeRoute(demoCase.route_status));
  setText("verdict-summary", demoCase.summary);
  setText("decision-basis", humanizeRoute(demoCase.decision_basis));
  setText("counterfactual", demoCase.counterfactual);
  renderRoutePill(demoCase.route_status);
  renderRequest(demoCase.request);
  renderFeatures("positive-features", demoCase.observer.positive, "chip-positive");
  renderFeatures("negative-features", demoCase.observer.negative, "chip-negative");
  renderStages(demoCase.stages);
}

function renderRoutePill(routeStatus) {
  const pill = document.getElementById("route-pill");
  pill.className = `route-pill ${routeClass(routeStatus)}`;
  pill.textContent = humanizeRoute(routeStatus);
}

function renderRequest(request) {
  const view = document.getElementById("request-view");
  view.textContent = JSON.stringify(request, null, 2);
}

function renderFeatures(id, items, className) {
  const host = document.getElementById(id);
  host.replaceChildren(...items.map((item) => {
    const chip = document.createElement("span");
    chip.className = `chip ${className}`;
    chip.textContent = item;
    return chip;
  }));
}

function renderStages(stages) {
  const host = document.getElementById("stage-grid");
  host.replaceChildren(...stages.map((stage) => {
    const card = document.createElement("article");
    card.className = "stage-card";
    card.innerHTML = `
      <div class="stage-head">
        <div class="stage-title">${escapeHtml(stage.label)}</div>
        <div class="stage-status ${statusClass(stage.status)}">${escapeHtml(stage.status)}</div>
      </div>
      <div class="bitmask">Bitmask: ${escapeHtml(String(stage.bitmask))}</div>
      <ul class="rule-list">
        ${(stage.triggered_rules.length ? stage.triggered_rules : ["no rules fired"]).map((rule) => `<li>${escapeHtml(rule)}</li>`).join("")}
      </ul>
    `;
    return card;
  }));
}

function humanizeRoute(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function routeClass(routeStatus) {
  if (routeStatus.startsWith("allow")) return "route-allow";
  if (routeStatus.startsWith("review")) return "route-review";
  return "route-deny";
}

function statusClass(status) {
  if (status === "allow") return "status-allow";
  if (status === "review") return "status-review";
  if (status === "deny") return "status-deny";
  return "status-quiet";
}

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) node.textContent = value || "";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeAttribute(value) {
  return escapeHtml(value);
}
