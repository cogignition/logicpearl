const params = new URLSearchParams(window.location.search);
const manifestPath = params.get("manifest") || "../healthcare_policy/demo_manifest.json";
const packsPath = "./packs.json";
const directManifestMode = params.has("manifest");
let loadedManifest = null;
let loadedCorpora = { papers: [] };
const casePaperCorpusCache = new Map();

async function main() {
  const packs = await loadJson(packsPath);
  renderGallery(packs.packs || []);
  const manifest = normalizeManifestPaths(await loadJson(manifestPath), manifestPath);
  loadedManifest = manifest;
  loadedCorpora = await loadSupportingCorpora(manifest);
  applyTheme(manifest.theme);
  renderHero(manifest);
  renderNav();
  renderStory(manifest.summary);
  renderSources(manifest.sources);
  await renderArtifacts(manifest.artifacts);
  renderCases(manifest.cases, manifest);
  const defaultCase = chooseDefaultCase(manifest.cases || []);
  if (defaultCase) {
    renderPatientFocus(defaultCase);
  }
}

async function loadJson(path) {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`Unable to load manifest: ${path}`);
  }
  return response.json();
}

function normalizeManifestPaths(manifest, manifestPathValue) {
  const manifestUrl = new URL(manifestPathValue, window.location.href);
  return {
    ...manifest,
    artifacts: (manifest.artifacts || []).map((artifact) => ({
      ...artifact,
      path: resolveRelativePath(manifestUrl, artifact.path)
    }))
  };
}

async function loadSupportingCorpora(manifest) {
  const literatureArtifact = (manifest.artifacts || []).find((artifact) =>
    String(artifact.label || "").toLowerCase().includes("literature corpus")
  );
  if (!literatureArtifact?.path) {
    return { papers: [] };
  }
  const papers = await loadJson(literatureArtifact.path);
  return {
    papers: (papers || []).map(normalizeCorpusPaper)
  };
}

function normalizeCorpusPaper(paper) {
  return {
    ...paper,
    concept_tags: Array.from(
      new Set([
        ...(paper.stage_tags || []),
        ...(paper.modality_tags || []),
        ...(paper.linked_mechanism_tags || [])
      ])
    )
  };
}

function resolveRelativePath(baseUrl, targetPath) {
  if (!targetPath) {
    return targetPath;
  }
  if (/^(https?:|data:)/.test(targetPath)) {
    return targetPath;
  }
  return new URL(targetPath, baseUrl).pathname;
}

function applyTheme(theme) {
  const root = document.documentElement;
  root.style.setProperty("--accent", theme.accent);
  root.style.setProperty("--surface", theme.surface);
  root.style.setProperty("--surface-alt", theme.surface_alt);
  root.style.setProperty("--text", theme.text);
  root.style.setProperty("--muted", theme.muted);
}

function renderHero(manifest) {
  setText("eyebrow", manifest.theme.name);
  setText("demo-title", manifest.title);
  setText("demo-subtitle", manifest.subtitle);
  setText("demo-tagline", manifest.tagline);

  const statsGrid = document.getElementById("stats-grid");
  statsGrid.replaceChildren(...manifest.stats.map(renderMetricCard));
}

function renderMetricCard(stat) {
  const card = document.createElement("article");
  card.className = "metric-card";
  card.innerHTML = `
    <div class="metric-label">${escapeHtml(stat.label)}</div>
    <div class="metric-value">${escapeHtml(stat.value)}</div>
    <div class="metric-note">${escapeHtml(stat.note || "")}</div>
  `;
  return card;
}

function renderNav() {
  const nav = document.getElementById("section-nav");
  const sections = [
    ["story", "Story"],
    ["sources", "Sources"],
    ["artifacts", "Artifacts"],
    ["cases", "Cases"],
    ["sharing", "Sharing"]
  ];
  if (!directManifestMode) {
    sections.unshift(["gallery", "Packs"]);
  }
  nav.replaceChildren(
    ...sections.map(([id, label]) => {
      const link = document.createElement("a");
      link.href = `#${id}`;
      link.textContent = label;
      return link;
    })
  );
}

function renderGallery(packs) {
  const section = document.getElementById("gallery");
  if (directManifestMode) {
    section?.setAttribute("hidden", "hidden");
    return;
  }
  section?.removeAttribute("hidden");
  const gallery = document.getElementById("gallery-grid");
  gallery.replaceChildren(...packs.map((pack) => {
    const card = document.createElement("article");
    card.className = "source-card";
    const href = `?manifest=${encodeURIComponent(pack.manifest)}`;
    card.innerHTML = `
      <div class="meta-label">Demo pack</div>
      <h3>${escapeHtml(pack.label)}</h3>
      <p>${escapeHtml(pack.description || "")}</p>
      <p><a href="${escapeAttribute(href)}">Open this pack</a></p>
      <div class="meta-note">${escapeHtml(pack.manifest)}</div>
    `;
    return card;
  }));
}

function renderStory(summary) {
  setText("problem-text", summary.problem);
  setText("why-text", summary.why_logicpearl);
  renderList("scope-list", summary.scope);
  renderList("non-goals-list", summary.non_goals);
}

function renderSources(sources) {
  const grid = document.getElementById("sources-grid");
  grid.replaceChildren(...sources.map((source) => {
    const card = document.createElement("article");
    card.className = "source-card";
    card.innerHTML = `
      <div class="meta-label">${escapeHtml(source.kind)}</div>
      <h3>${escapeHtml(source.title)}</h3>
      <div class="meta-note">${escapeHtml(source.publisher)}</div>
      <p>${escapeHtml(source.note || "")}</p>
      ${source.url ? `<p><a href="${escapeAttribute(source.url)}">Open source</a></p>` : ""}
      <div class="meta-note">ID: ${escapeHtml(source.id)}</div>
      <div class="meta-note">Last updated: ${escapeHtml(source.last_updated || "unknown")}</div>
    `;
    return card;
  }));
}

async function renderArtifacts(artifacts) {
  const grid = document.getElementById("artifacts-grid");
  const previewList = document.getElementById("artifact-preview-list");

  const cards = artifacts.map((artifact) => {
    const card = document.createElement("article");
    card.className = "artifact-card";
    card.innerHTML = `
      <div class="meta-label">${escapeHtml(artifact.kind)}</div>
      <h3>${escapeHtml(artifact.label)}</h3>
      <p>${escapeHtml(artifact.description || "")}</p>
      <p><a href="${escapeAttribute(artifact.path)}">Open artifact</a></p>
      <div class="meta-note">${escapeHtml(artifact.path)}</div>
    `;
    return card;
  });
  grid.replaceChildren(...cards);

  const buttons = artifacts.map((artifact, index) => {
    const button = document.createElement("button");
    button.className = "case-button";
    button.type = "button";
    button.innerHTML = `
      <div class="case-title">${escapeHtml(artifact.label)}</div>
      <div>${escapeHtml(artifact.description || artifact.kind)}</div>
      <div class="case-result">${escapeHtml(artifact.kind)}</div>
    `;
    button.addEventListener("click", async () => {
      buttons.forEach((entry) => entry.classList.remove("active"));
      button.classList.add("active");
      await renderArtifactPreview(artifact);
    });
    if (index === 0) {
      button.classList.add("active");
    }
    return button;
  });

  previewList.replaceChildren(...buttons);
  if (artifacts.length > 0) {
    await renderArtifactPreview(artifacts[0]);
  }
}

function renderCases(cases, manifest) {
  const caseList = document.getElementById("case-list");
  const caseDetail = document.getElementById("case-detail");
  const defaultCase = chooseDefaultCase(cases);

  const buttons = cases.map((demoCase, index) => {
    const button = document.createElement("button");
    button.className = "case-button";
    button.type = "button";
    button.innerHTML = `
      <div class="case-title">${escapeHtml(demoCase.title)}</div>
      <div>${escapeHtml(demoCase.summary)}</div>
      <div class="case-result">${escapeHtml(demoCase.result)}</div>
    `;
    button.addEventListener("click", () => {
      buttons.forEach((entry) => entry.classList.remove("active"));
      button.classList.add("active");
      renderPatientFocus(demoCase);
      renderCaseDetail(caseDetail, demoCase, manifest);
    });
    if ((defaultCase && demoCase.case_id === defaultCase.case_id) || (!defaultCase && index === 0)) {
      button.classList.add("active");
      renderPatientFocus(demoCase);
      renderCaseDetail(caseDetail, demoCase, manifest);
    }
    return button;
  });

  caseList.replaceChildren(...buttons);
}

function chooseDefaultCase(cases) {
  return cases.find((item) => item.case_id === "case_postop_radiation_in_progress") || cases[0] || null;
}

function renderPatientFocus(demoCase) {
  setText("focus-title", demoCase.title);
  setText("focus-status", friendlyCaseResult(demoCase));
  setText("focus-summary", buildPatientFocusSummary(demoCase));
  renderFocusActions(demoCase);
  const grid = document.getElementById("focus-grid");
  const panels = [
    renderFocusPanel("1. Where Things Stand", buildSituationLines(demoCase)),
    renderFocusPanel("2. Best Next Moves", buildDiscussNowLines(demoCase)),
    renderFocusPanel("3. What Could Unlock More Options", buildBlockerLines(demoCase)),
    renderFocusPanel("Fast Research Entry Points", buildResearchLines(demoCase))
  ];
  grid.replaceChildren(...panels);
}

function renderFocusActions(demoCase) {
  const host = document.getElementById("focus-actions");
  if (!host) return;
  const actions = [];
  const topTrial = (demoCase.related_trials || []).find((item) => item.status === "candidate_for_review" && item.source_url);
  const topPaper = (demoCase.related_papers || []).find((item) => item.source_url);
  const topDataset = (demoCase.related_datasets || []).find((item) => item.url);
  if (topTrial) {
    actions.push(renderFocusLink(buildTopTrialLabel(topTrial), topTrial.source_url, false));
  }
  if (topPaper) {
    actions.push(renderFocusLink(buildTopPaperLabel(topPaper), topPaper.source_url, true));
  }
  if (topDataset) {
    actions.push(renderFocusLink(buildTopDatasetLabel(topDataset), topDataset.url, true));
  }
  if (!actions.length) {
    host.replaceChildren();
    return;
  }
  host.replaceChildren(...actions);
}

function renderFocusLink(label, href, secondary) {
  const link = document.createElement("a");
  link.className = `focus-link${secondary ? " focus-link-secondary" : ""}`;
  link.href = href;
  link.target = "_blank";
  link.rel = "noreferrer";
  link.textContent = label;
  return link;
}

function renderFocusPanel(title, lines) {
  const panel = document.createElement("article");
  panel.className = "focus-panel";
  const body = Array.isArray(lines)
    ? `<ul class="focus-list">${lines.map(renderFocusLine).join("")}</ul>`
    : `<div class="focus-copy">${escapeHtml(lines)}</div>`;
  panel.innerHTML = `
    <h3>${escapeHtml(title)}</h3>
    ${body}
  `;
  return panel;
}

function renderFocusLine(line) {
  if (typeof line === "string") {
    return `<li>${escapeHtml(line)}</li>`;
  }
  if (line && typeof line === "object") {
    const prefix = line.prefix ? `${escapeHtml(line.prefix)} ` : "";
    const suffix = line.suffix ? ` ${escapeHtml(line.suffix)}` : "";
    const body = line.href
      ? `<a class="focus-inline-link" href="${escapeAttribute(line.href)}" target="_blank" rel="noreferrer">${escapeHtml(line.label || line.href)}</a>`
      : escapeHtml(line.label || "");
    return `<li>${prefix}${body}${suffix}</li>`;
  }
  return `<li>${escapeHtml(String(line))}</li>`;
}

function friendlyCaseResult(demoCase) {
  if (demoCase.trial_counts?.candidate > 0) {
    return "Options to review now";
  }
  if ((demoCase.missing_evidence || []).length > 0) {
    return "More information would unlock more options";
  }
  return demoCase.result || "Review in progress";
}

function buildPatientFocusSummary(demoCase) {
  const candidateCount = demoCase.trial_counts?.candidate ?? 0;
  const blockerCount = (demoCase.missing_evidence || []).length;
  const treatmentCount = (demoCase.treatment_options || []).length;
  const trialPhrase = candidateCount === 1 ? "1 research option to review now" : `${candidateCount} research options to review now`;
  const blockerPhrase = blockerCount === 0 ? "no major evidence blockers are currently surfaced" : `${blockerCount} missing items are still limiting the wider search`;
  return `${demoCase.summary} Right now, the system sees ${treatmentCount} treatment paths to discuss, ${trialPhrase}, and ${blockerPhrase}. The links below go straight to the most relevant live sources so you do not have to hunt through the full corpus first.`;
}

function buildSituationLines(demoCase) {
  const graph = demoCase.evidence_graph || {};
  return [
    demoCase.summary,
    `The strongest organizing ideas for this case are ${(graph.top_concepts || []).slice(0, 4).map((item) => item.replaceAll("_", " ")).join(", ") || "current treatment state"}.`,
    `This case is being surfaced first because it matches the patient profile you asked for: a 52-year-old man with a resected 2 cm tumor currently in radiation.`
  ];
}

function buildDiscussNowLines(demoCase) {
  const lines = [];
  if ((demoCase.treatment_options || []).length) {
    lines.push(...demoCase.treatment_options.slice(0, 3).map((item) => `Discuss treatment path: ${item}. Why: it fits the newly diagnosed, postoperative, good-performance-status state.`));
  }
  const candidateTrials = (demoCase.related_trials || []).filter((item) => item.status === "candidate_for_review");
  if (candidateTrials.length) {
    lines.push(
      ...candidateTrials.slice(0, 2).map((item) => ({
        prefix: "Research option worth a closer look:",
        label: item.title,
        href: item.source_url,
        suffix: `Why: ${(item.reasons || []).slice(0, 2).join(" ") || "it matches the current patient state."}`
      }))
    );
  }
  if (!lines.length) {
    lines.push("No immediate research option stands out yet; focus on completing the evidence package first.");
  }
  return lines;
}

function buildBlockerLines(demoCase) {
  if (!(demoCase.missing_evidence || []).length) {
    return ["No major missing evidence is currently blocking additional review paths."];
  }
  return demoCase.missing_evidence
    .slice(0, 4)
    .map((item) => `Missing or incomplete: ${item}. This matters because it can block trial matching or narrow the evidence review.`);
}

function buildResearchLines(demoCase) {
  const lines = [];
  if ((demoCase.related_papers || []).length) {
    lines.push({
      prefix: "Start with this paper:",
      label: demoCase.related_papers[0].title,
      href: demoCase.related_papers[0].source_url,
      suffix: demoCase.related_papers[0].human_summary
    });
  }
  if ((demoCase.related_datasets || []).length) {
    lines.push({
      prefix: "Useful data reference:",
      label: demoCase.related_datasets[0].title,
      href: demoCase.related_datasets[0].url,
      suffix: "This helps when you want biomarker or cohort-level context instead of just one trial page."
    });
  }
  if ((demoCase.related_trials || []).length > (demoCase.trial_counts?.candidate ?? 0)) {
    lines.push("Use the graph and tabs below to move from the top recommendation into broader research, including things that do not currently fit.");
  }
  return lines.length ? lines : ["No additional research context loaded for this case."];
}

function buildTopTrialLabel(trial) {
  const text = `${trial.title || ""} ${trial.human_summary || ""}`.toLowerCase();
  if (text.includes("newly diagnosed")) return "Open best newly diagnosed trial";
  if (text.includes("recurrent")) return "Open best recurrent-disease trial";
  return "Open top matching trial";
}

function buildTopPaperLabel(paper) {
  if (paper.evidence_bucket === "guideline") return "Open best standard-care reference";
  const text = `${paper.title || ""} ${paper.human_summary || ""}`.toLowerCase();
  if (text.includes("newly diagnosed")) return "Open best paper for this stage";
  return "Open best background paper";
}

function buildTopDatasetLabel(dataset) {
  if (dataset.dataset_type === "genomics") return "Open GBM genomics dataset";
  if (dataset.dataset_type === "atlas") return "Open GBM atlas dataset";
  return "Open supporting dataset";
}

function renderCaseDetail(container, demoCase, manifest) {
  container.__demoCase = demoCase;
  container.__manifest = manifest;
  const failed = demoCase.failed_requirements || [];
  const blockedArchetypes = demoCase.blocked_archetypes || [];
  const missingEvidence = demoCase.missing_evidence || [];
  const treatmentOptions = demoCase.treatment_options || [];
  const trialOptions = demoCase.trial_options || [];
  const historicalSignals = demoCase.historical_signals || [];
  const relatedTrials = demoCase.related_trials || [];
  const relatedPapers = demoCase.related_papers || [];
  const relatedDatasets = demoCase.related_datasets || [];
  const trialCounts = demoCase.trial_counts || {};
  const graphMeta = demoCase.evidence_graph || {};
  const state = {
    mode: "patient",
    concept: null,
    trialStatus: "all",
    trialQuery: "",
    trialPage: 1,
    selectedEvidence: null,
    activeTab: "overview",
    paperView: "start_here",
    paperQuery: "",
    paperPage: 1,
    paperAbstractOnly: false
  };
  container.__workspaceState = state;
  const requirementCards = (demoCase.requirements || []).map((requirement) => {
    const article = document.createElement("article");
    article.className = "requirement-card";
    article.id = requirementDomId(requirement.requirement_id);
    article.dataset.requirementId = requirement.requirement_id || "";
    const statusClass = requirement.satisfied ? "status-ok" : "status-missing";
    const supportingArtifacts = requirement.supporting_artifact_ids || [];
    const missingArtifactTypes = requirement.missing_artifact_types || [];
    article.innerHTML = `
      <div class="requirement-status ${statusClass}">
        ${escapeHtml(requirement.evidence_status || requirement.status || (requirement.satisfied ? "Ready" : "Incomplete"))}
      </div>
      <h3>${escapeHtml(requirement.label || requirement.requirement_id)}</h3>
      ${requirement.question_text ? `<p>${escapeHtml(requirement.question_text)}</p>` : ""}
      <div class="kv">
        <div>Requirement ID: ${escapeHtml(requirement.requirement_id || "n/a")}</div>
        <div>Source: ${escapeHtml(requirement.source_id || "n/a")}</div>
        <div>Evidence status: ${escapeHtml(requirement.evidence_status || requirement.status || (requirement.satisfied ? "ready" : "incomplete"))}</div>
        <div>Supporting artifacts: ${escapeHtml(supportingArtifacts.join(", ") || "none")}</div>
        <div>Missing artifact types: ${escapeHtml(missingArtifactTypes.join(", ") || "none")}</div>
      </div>
      <p>${escapeHtml(requirement.evidence_needed || requirement.source_excerpt || "")}</p>
    `;
    return article;
  });

  const requirementContent = requirementCards.length
    ? ""
    : `<div class="empty-state">No per-requirement detail provided in this demo pack.</div>`;

  container.innerHTML = `
    <section class="artifact-card">
      <div class="detail-header">
        <div>
          <div class="meta-label">Selected Scenario</div>
          <h3>${escapeHtml(demoCase.title)}</h3>
        </div>
        <div class="case-result">${escapeHtml(friendlyCaseResult(demoCase))}</div>
      </div>
      <p class="detail-summary">${escapeHtml(demoCase.summary)}</p>
      <div class="pill-row">
        <span class="pill">${escapeHtml(String(trialCounts.candidate ?? trialOptions.length))} research options now</span>
        <span class="pill">${escapeHtml(String(trialCounts.needs_more_evidence ?? 0))} need more evidence</span>
        <span class="pill">${escapeHtml(String((missingEvidence || []).length))} evidence gaps</span>
        <span class="pill">${escapeHtml(String(trialCounts.papers ?? relatedPapers.length))} papers</span>
        <span class="pill">${escapeHtml(String(relatedPapers.filter((item) => item.abstract_excerpt).length))} with local abstracts</span>
        <span class="pill">${escapeHtml(fullCorpusPapersLabel())}</span>
        <span class="pill">${escapeHtml(String(trialCounts.datasets ?? relatedDatasets.length))} datasets</span>
      </div>
      <details class="collapsible-section inline-collapsible">
        <summary class="collapsible-summary">
          <span>Technical Snapshot</span>
          <span class="meta-note">Case ids, bitmask, blockers, and historical items</span>
        </summary>
        <div class="pill-row">
          <span class="pill">Case ID: ${escapeHtml(demoCase.case_id)}</span>
          <span class="pill">Bitmask: ${escapeHtml(String(demoCase.bitmask ?? "n/a"))}</span>
        </div>
        <div class="pill-row">
          ${(failed.length ? failed : ["no failed requirements"]).map((item) => `<span class="pill">${escapeHtml(item)}</span>`).join("")}
        </div>
        <div class="pill-row">
          ${(blockedArchetypes.length ? blockedArchetypes : ["No blocked archetypes"]).map((item) => `<span class="pill">${escapeHtml(item)}</span>`).join("")}
        </div>
        <div class="pill-row">
          ${(historicalSignals.length ? historicalSignals : ["No historical signals loaded"]).map((item) => `<span class="pill">${escapeHtml(item)}</span>`).join("")}
        </div>
      </details>
    </section>
    <section class="workspace-shell">
      <div class="workspace-intro">
        <div class="meta-label">Choose Where To Explore</div>
        <p class="meta-note">Start with the lane that matches what you need right now: the big-picture view, live research options, papers, or data.</p>
      </div>
      <div class="workspace-tabs">
        <button class="workspace-tab active" data-tab="overview" type="button">
          <span class="workspace-tab-label">Overview</span>
          <span class="workspace-tab-note">Graph and requirements</span>
        </button>
        <button class="workspace-tab" data-tab="research" type="button">
          <span class="workspace-tab-label">Research Options</span>
          <span class="workspace-tab-note">Trials and fit reasoning</span>
        </button>
        <button class="workspace-tab" data-tab="reading" type="button">
          <span class="workspace-tab-label">Reading</span>
          <span class="workspace-tab-note">Papers and abstracts</span>
        </button>
        <button class="workspace-tab" data-tab="data" type="button">
          <span class="workspace-tab-label">Data</span>
          <span class="workspace-tab-note">Datasets and cohorts</span>
        </button>
      </div>
      <div id="workspace-overview" class="workspace-panel active">
        <section class="graph-shell">
          <div class="graph-panel">
            <div class="section-header">
              <div>
                <h3>Evidence Graph</h3>
                <p class="meta-note">Patient-centered by default. Click a concept or evidence node to filter the review panels.</p>
              </div>
            </div>
            <div class="graph-toolbar">
              <button id="graph-mode-patient" class="case-button active" type="button">Patient View</button>
              <button id="graph-mode-research" class="case-button" type="button">Research View</button>
              <button id="graph-reset" class="case-button" type="button">Reset Focus</button>
            </div>
            <div id="graph-canvas" class="graph-canvas"></div>
            <div class="graph-caption">
              Graph slice: ${escapeHtml(String(graphMeta.node_count ?? "n/a"))} nodes, ${escapeHtml(String(graphMeta.edge_count ?? "n/a"))} edges.
            </div>
          </div>
          <aside class="graph-sidepanel">
            <section class="graph-panel">
              <div class="meta-label">Active Focus</div>
              <div id="graph-focus-title" class="case-title">Patient overview</div>
              <p id="graph-focus-description" class="meta-note">Showing the default patient-centered evidence neighborhood.</p>
            </section>
        <section class="graph-panel">
          <div class="meta-label">Concepts</div>
          <p class="meta-note">These are the main ideas driving the current case, like newly diagnosed disease, radiation, biomarkers, or performance status. Click one to filter the page around that topic.</p>
          <div id="concept-filter-row" class="pill-row"></div>
        </section>
            <section class="graph-panel">
              <div class="meta-label">Legend</div>
              <div class="graph-legend">
                <div class="legend-row"><span class="legend-dot" style="background:#17272a;"></span>Patient</div>
                <div class="legend-row"><span class="legend-dot" style="background:#0f7c7a;"></span>Concept</div>
                <div class="legend-row"><span class="legend-dot" style="background:#2d6cdf;"></span>Matched trial</div>
                <div class="legend-row"><span class="legend-dot" style="background:#c9861a;"></span>Needs evidence</div>
                <div class="legend-row"><span class="legend-dot" style="background:#8b97a6;"></span>Historical / unlikely</div>
                <div class="legend-row"><span class="legend-dot" style="background:#4466bb;"></span>Paper</div>
                <div class="legend-row"><span class="legend-dot" style="background:#14806a;"></span>Dataset</div>
              </div>
            </section>
          </aside>
        </section>
        <section>
          <div class="section-header">
            <h3>Requirement Status</h3>
          </div>
          <div id="requirement-grid" class="requirement-grid">${requirementContent}</div>
        </section>
      </div>
      <div id="workspace-research" class="workspace-panel">
        <section>
          <div class="section-header">
            <h3>Related Trials</h3>
          </div>
          <div id="trial-filter-row" class="pill-row"></div>
          <div id="trial-browser-shell"></div>
          <div id="trial-catalog" class="requirement-grid"></div>
        </section>
      </div>
      <div id="workspace-reading" class="workspace-panel">
        <section>
          <div class="section-header">
            <h3>Related Papers</h3>
          </div>
          <div id="paper-browser-shell"></div>
          <div id="paper-catalog" class="requirement-grid"></div>
        </section>
      </div>
      <div id="workspace-data" class="workspace-panel">
        <section>
          <div class="section-header">
            <h3>Related Datasets</h3>
          </div>
          <div id="dataset-catalog" class="requirement-grid"></div>
        </section>
      </div>
    </section>
  `;

  if (requirementCards.length) {
    container.querySelector("#requirement-grid").replaceChildren(...requirementCards);
  }

  wireRequirementJumpLinks(container);
  wireGraphModeControls(container, state);
  wireWorkspaceTabs(container, state, demoCase);
  wireConceptFilters(container.querySelector("#concept-filter-row"), demoCase, state);
  syncGraphModeButtons(container, state);
  syncWorkspaceTabs(container, state);
  renderSelectedEvidence(null, demoCase);
  renderEvidenceView(container, demoCase, state);
}

function renderEvidenceView(container, demoCase, state) {
  renderGraphFocus(
    container.querySelector("#graph-focus-title"),
    container.querySelector("#graph-focus-description"),
    state
  );
  renderEvidenceGraph(container.querySelector("#graph-canvas"), demoCase, state, (kind, value) => {
    if (kind === "concept") {
      state.concept = state.concept === value ? null : value;
      state.selectedEvidence = state.concept ? { kind: "concept", value } : null;
      renderSelectedEvidence(state.selectedEvidence, demoCase);
      renderEvidenceView(container, demoCase, state);
      syncConceptButtons(container.querySelector("#concept-filter-row"), state);
      return;
    }
    if (kind === "mode") {
      state.mode = value;
      renderEvidenceView(container, demoCase, state);
      syncGraphModeButtons(container, state);
      return;
    }
    if (kind === "trial" || kind === "paper" || kind === "dataset") {
      state.selectedEvidence = { kind, value };
      renderSelectedEvidence(state.selectedEvidence, demoCase);
    }
  });
  renderTrialCatalog(
    container.querySelector("#trial-filter-row"),
    container.querySelector("#trial-catalog"),
    demoCase.related_trials || [],
    state,
    demoCase
  );
  renderPaperCatalog(container.querySelector("#paper-catalog"), demoCase.related_papers || [], state, demoCase);
  renderDatasetCatalog(container.querySelector("#dataset-catalog"), demoCase.related_datasets || [], state, demoCase);
}

function renderTrialCatalog(filterRow, catalog, trials, state, demoCase) {
  const browserShell = document.getElementById("trial-browser-shell");
  if (!catalog || !filterRow || !browserShell) {
    return;
  }
  const filterDefs = [
    ["all", "All related"],
    ["candidate_for_review", "Matches"],
    ["needs_more_evidence", "Needs evidence"],
    ["unlikely_fit_now", "Not now"],
    ["historical_signal", "Historical"]
  ];
  const buttons = filterDefs.map(([value, label]) => {
    const button = document.createElement("button");
    button.className = "case-button";
    button.type = "button";
    button.textContent = label;
    button.addEventListener("click", () => {
      state.trialStatus = value;
      state.trialPage = 1;
      syncTrialStatusButtons(filterRow, state);
      renderTrialCatalog(filterRow, catalog, trials, state, demoCase);
    });
    return button;
  });
  filterRow.replaceChildren(...buttons);
  syncTrialStatusButtons(filterRow, state);
  const filtered = filterEvidenceItems(trials, state, "trial");
  const searched = filterTrialsForBrowser(filtered, state)
    .slice()
    .sort((left, right) => scoreTrialForCase(right, demoCase) - scoreTrialForCase(left, demoCase));
  renderTrialBrowserShell(browserShell, trials, filtered, searched, state, demoCase, catalog, filterRow);

  if (!searched.length) {
    catalog.innerHTML = `<div class="empty-state">No trials in this filter.</div>`;
    return;
  }
  if (shouldShowGroupedTrials(state)) {
    renderGroupedTrialCatalog(catalog, searched, state, demoCase);
    return;
  }

  const pageSize = 24;
  const totalPages = Math.max(1, Math.ceil(searched.length / pageSize));
  state.trialPage = Math.min(state.trialPage, totalPages);
  const start = (state.trialPage - 1) * pageSize;
  const visible = searched.slice(start, start + pageSize);
  if (!visible.length) {
    state.trialPage = 1;
    return renderTrialCatalog(filterRow, catalog, trials, state, demoCase);
  }
  catalog.replaceChildren(...visible.map((trial) => renderTrialCard(trial, state, demoCase)));
}

function renderTrialCard(trial, state, demoCase) {
  const article = document.createElement("article");
  article.className = "requirement-card";
  const reasons = trial.reasons || [];
  const comparisons = trial.normalized_comparisons || [];
  const missingLabels = trial.missing_requirement_labels || [];
  const readyLabels = trial.ready_requirement_labels || [];
  const ranking = buildRankingExplanation("trial", trial, demoCase);
  article.innerHTML = `
    <div class="requirement-status ${statusClassForTrial(trial.status)}">
      ${escapeHtml(trial.status || "related")}
    </div>
    <h3>${escapeHtml(trial.trial_id || "trial")} · ${escapeHtml(trial.title || "")}</h3>
    <p>${escapeHtml(trial.human_summary || trial.summary || "")}</p>
    <div class="kv">
      <div>Priority: ${escapeHtml(String(trial.review_priority_score ?? "n/a"))}</div>
      <div>Phase: ${escapeHtml(trial.phase || "n/a")}</div>
      <div>Status: ${escapeHtml(trial.recruitment_status || "n/a")}</div>
      <div>Bucket: ${escapeHtml(trial.actionability_bucket || "n/a")}</div>
    </div>
    <p><strong>Why this rose:</strong> ${escapeHtml(ranking.summary)}</p>
    <div class="kv">
      <div>Rank score: ${escapeHtml(String(ranking.totalScore))}</div>
      <div>Requirement support: ${renderRequirementJumpControl("support", trial.ready_requirement_ids || [], ranking.supportCount, "supported")}</div>
      <div>Requirement blockers: ${renderRequirementJumpControl("blockers", trial.missing_requirement_ids || [], ranking.blockedCount, "blocked")}</div>
      <div>Bitmask contribution: ${escapeHtml(String(ranking.maskScore))}</div>
    </div>
    <p>${escapeHtml(reasons.join(" | ") || "No reasoning generated.")}</p>
    <p>${escapeHtml(formatComparisons(comparisons))}</p>
    ${readyLabels.length ? `<p><strong>Supported by:</strong> ${escapeHtml(readyLabels.slice(0, 4).join(", "))}</p>` : ""}
    ${missingLabels.length ? `<p><strong>Blocked by missing:</strong> ${escapeHtml(missingLabels.slice(0, 4).join(", "))}</p>` : ""}
    ${trial.source_url ? `<p><a href="${escapeAttribute(trial.source_url)}">Open study</a></p>` : ""}
  `;
  article.addEventListener("click", () => {
    state.selectedEvidence = { kind: "trial", value: trial.trial_id };
    renderSelectedEvidence(state.selectedEvidence, demoCase);
  });
  return article;
}

function renderTrialBrowserShell(host, allTrials, filteredTrials, searchedTrials, state, demoCase, catalog, filterRow) {
  const grouped = groupTrialsByStatus(filteredTrials);
  const topMatches = grouped.candidate_for_review.slice(0, 3);
  const totalPages = Math.max(1, Math.ceil(searchedTrials.length / 24));
  state.trialPage = Math.min(state.trialPage, totalPages);
  host.innerHTML = `
    <div class="paper-browser-shell">
      <div class="paper-browser-metrics">
        <article class="metric-card compact">
          <div class="metric-label">All related trials</div>
          <div class="metric-value">${escapeHtml(String(allTrials.length))}</div>
          <div class="metric-note">Everything currently connected to this case.</div>
        </article>
        <article class="metric-card compact">
          <div class="metric-label">Matches now</div>
          <div class="metric-value">${escapeHtml(String(grouped.candidate_for_review.length))}</div>
          <div class="metric-note">Best current fits for review.</div>
        </article>
        <article class="metric-card compact">
          <div class="metric-label">Need more evidence</div>
          <div class="metric-value">${escapeHtml(String(grouped.needs_more_evidence.length))}</div>
          <div class="metric-note">Could matter if more data is added.</div>
        </article>
        <article class="metric-card compact">
          <div class="metric-label">Not now / historical</div>
          <div class="metric-value">${escapeHtml(String(grouped.unlikely_fit_now.length + grouped.historical_signal.length))}</div>
          <div class="metric-note">Still useful for context and failure patterns.</div>
        </article>
      </div>
      <div class="paper-start-here">
        <div class="section-header compact-header">
          <div>
            <h4>Start Here</h4>
            <p class="meta-note">This is the shortest path into the trial landscape for this patient state.</p>
          </div>
        </div>
        <div class="paper-start-grid">
          ${topMatches.length ? topMatches.map((trial) => renderStartHereTrialCard(trial)).join("") : `<div class="empty-state">No current match stands out. Move to the “Needs evidence” section or use search.</div>`}
        </div>
      </div>
      <div class="paper-browser-toolbar">
        <label class="paper-search">
          <span class="meta-label">Search trials</span>
          <input id="trial-search-input" type="search" value="${escapeAttribute(state.trialQuery || "")}" placeholder="Search NCT ID, title, phase, modality, status, or biomarker" />
        </label>
        <div class="paper-browser-caption">
          ${shouldShowGroupedTrials(state)
            ? `Grouped landscape view. Showing ${escapeHtml(String(searchedTrials.length))} trials across match, blocker, not-now, and historical sections.`
            : `Page ${escapeHtml(String(state.trialPage))} of ${escapeHtml(String(totalPages))}.`}
        </div>
      </div>
      ${shouldShowGroupedTrials(state) ? "" : `
      <div class="paper-pagination">
        <button id="trial-prev-page" class="case-button" type="button" ${state.trialPage <= 1 ? "disabled" : ""}>Previous</button>
        <button id="trial-next-page" class="case-button" type="button" ${state.trialPage >= totalPages ? "disabled" : ""}>Next</button>
      </div>`}
    </div>
  `;

  host.querySelector("#trial-search-input")?.addEventListener("input", (event) => {
    const input = event.target;
    state.trialQuery = input.value;
    state.trialPage = 1;
    rerenderPreservingSearchPosition(() => {
      renderTrialCatalog(filterRow, catalog, allTrials, state, demoCase);
    }, "#trial-search-input", state.trialQuery, input.selectionStart ?? state.trialQuery.length);
  });
  host.querySelector("#trial-prev-page")?.addEventListener("click", () => {
    state.trialPage = Math.max(1, state.trialPage - 1);
    renderTrialCatalog(filterRow, catalog, allTrials, state, demoCase);
  });
  host.querySelector("#trial-next-page")?.addEventListener("click", () => {
    state.trialPage += 1;
    renderTrialCatalog(filterRow, catalog, allTrials, state, demoCase);
  });
  host.querySelectorAll("[data-trial-id]").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedEvidence = { kind: "trial", value: button.dataset.trialId };
      renderSelectedEvidence(state.selectedEvidence, demoCase);
    });
  });
}

function renderGroupedTrialCatalog(catalog, trials, state, demoCase) {
  const grouped = groupTrialsByStatus(trials);
  const sections = [
    ["Best matches now", grouped.candidate_for_review, "Why these are strongest now"],
    ["Could matter if more evidence is added", grouped.needs_more_evidence, "These are blocked by missing information, not immediate mismatch"],
    ["Probably not a fit now", grouped.unlikely_fit_now, "Relevant to the disease, but currently mismatched for this patient state"],
    ["Historical or prior signal", grouped.historical_signal, "Older, completed, suspended, or otherwise non-current studies that may still teach something"]
  ];
  const cards = sections
    .filter(([, items]) => items.length)
    .map(([title, items, note]) => {
      const section = document.createElement("section");
      section.className = "paper-start-here";
      section.innerHTML = `
        <div class="section-header compact-header">
          <div>
            <h4>${escapeHtml(title)}</h4>
            <p class="meta-note">${escapeHtml(note)}</p>
          </div>
          <div class="case-result">${escapeHtml(String(items.length))}</div>
        </div>
      `;
      const grid = document.createElement("div");
      grid.className = "requirement-grid";
      items
        .slice()
        .sort((left, right) => scoreTrialForCase(right, demoCase) - scoreTrialForCase(left, demoCase))
        .slice(0, 18)
        .forEach((trial) => grid.appendChild(renderTrialCard(trial, state, demoCase)));
      if (items.length > 18) {
        const more = document.createElement("div");
        more.className = "empty-state";
        more.textContent = `${items.length - 18} more in this group. Use search or a specific status filter to browse them in a paged list.`;
        grid.appendChild(more);
      }
      section.appendChild(grid);
      return section;
    });
  catalog.replaceChildren(...cards);
}

function renderStartHereTrialCard(trial) {
  const demoCase = document.getElementById("case-detail")?.__demoCase;
  const ranking = demoCase ? buildRankingExplanation("trial", trial, demoCase) : null;
  return `
    <article class="source-card start-here-card" data-trial-id="${escapeAttribute(trial.trial_id)}">
      <div class="meta-label">${escapeHtml(trial.status || "trial")}</div>
      <h4>${escapeHtml(trial.trial_id || "trial")} · ${escapeHtml(trial.title || "")}</h4>
      <p>${escapeHtml(trial.human_summary || trial.summary || "")}</p>
      <div class="meta-note">Priority ${escapeHtml(String(trial.review_priority_score ?? "n/a"))} · ${escapeHtml(trial.phase || "n/a")} · ${escapeHtml(trial.recruitment_status || "n/a")}</div>
      ${ranking ? `<p class="meta-note"><strong>Why this rose:</strong> ${escapeHtml(ranking.summary)}</p>` : ""}
      ${ranking ? `<p class="meta-note">Jump to: ${renderRequirementJumpControl("support", trial.ready_requirement_ids || [], ranking.supportCount, "supported")} · ${renderRequirementJumpControl("blockers", trial.missing_requirement_ids || [], ranking.blockedCount, "blocked")}</p>` : ""}
      ${trial.source_url ? `<p><a href="${escapeAttribute(trial.source_url)}" target="_blank" rel="noreferrer">Open study</a></p>` : ""}
    </article>
  `;
}

function groupTrialsByStatus(trials) {
  return {
    candidate_for_review: trials.filter((item) => item.status === "candidate_for_review"),
    needs_more_evidence: trials.filter((item) => item.status === "needs_more_evidence"),
    unlikely_fit_now: trials.filter((item) => item.status === "unlikely_fit_now"),
    historical_signal: trials.filter((item) => item.status === "historical_signal")
  };
}

function filterTrialsForBrowser(trials, state) {
  const query = (state.trialQuery || "").trim().toLowerCase();
  return trials.filter((trial) => {
    if (!query) {
      return true;
    }
    const haystack = [
      trial.trial_id,
      trial.title,
      trial.human_summary,
      trial.phase,
      trial.recruitment_status,
      trial.actionability_bucket,
      trial.primary_purpose,
      trial.treatment_modality,
      (trial.concept_tags || []).join(" "),
      (trial.reasons || []).join(" ")
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return haystack.includes(query);
  });
}

function shouldShowGroupedTrials(state) {
  return state.trialStatus === "all" && !(state.trialQuery || "").trim();
}

function renderPaperCatalog(catalog, papers, state, demoCase) {
  const browserShell = document.getElementById("paper-browser-shell");
  if (!catalog || !browserShell) {
    return;
  }
  const corpusPapers = getCasePaperCorpus(demoCase);
  const hasFullCorpus = corpusPapers.length > 0;
  if (!hasFullCorpus) {
    state.paperView = "start_here";
  }
  const filtered = filterEvidenceItems(corpusPapers, state, "paper");
  const searched = filterPapersForBrowser(filtered, state)
    .slice()
    .sort((left, right) => scorePaperForCase(right, demoCase) - scorePaperForCase(left, demoCase));
  renderPaperBrowserShell(browserShell, corpusPapers, filtered, searched, state, demoCase, catalog, papers);
  if (state.paperView === "start_here") {
    const startHere = buildStartHerePapers(demoCase, papers);
    if (!startHere.length) {
      catalog.innerHTML = `<div class="empty-state">No start-here papers available for this case.</div>`;
      return;
    }
    catalog.replaceChildren(...startHere.map((paper) => {
      const article = document.createElement("article");
      article.className = "requirement-card";
      const linkedTrials = (paper.linked_trial_ids || []).slice(0, 3);
      const missingLabels = paper.missing_requirement_labels || [];
      const readyLabels = paper.ready_requirement_labels || [];
      const ranking = buildRankingExplanation("paper", paper, demoCase);
      article.innerHTML = `
        <div class="requirement-status status-ok">${escapeHtml(paper.evidence_bucket || "paper")}</div>
        <h3>${escapeHtml(paper.paper_id || "paper")} · ${escapeHtml(paper.title || "")}</h3>
        <p>${escapeHtml(paper.human_summary || "")}</p>
        <div class="kv">
          <div>Journal: ${escapeHtml(paper.journal || "n/a")}</div>
          <div>Year: ${escapeHtml(String(paper.publication_year || "n/a"))}</div>
          <div>Abstract: ${escapeHtml(paper.abstract_excerpt ? "loaded" : "metadata only")}</div>
          <div>Linked trials: ${escapeHtml(linkedTrials.join(", ") || "none")}</div>
        </div>
        <p><strong>Why this rose:</strong> ${escapeHtml(ranking.summary)}</p>
        <div class="kv">
          <div>Rank score: ${escapeHtml(String(ranking.totalScore))}</div>
          <div>Requirement support: ${renderRequirementJumpControl("support", paper.ready_requirement_ids || [], ranking.supportCount, "supported")}</div>
          <div>Requirement blockers: ${renderRequirementJumpControl("blockers", paper.missing_requirement_ids || [], ranking.blockedCount, "blocked")}</div>
          <div>Bitmask contribution: ${escapeHtml(String(ranking.maskScore))}</div>
        </div>
        ${readyLabels.length ? `<p><strong>Supported by:</strong> ${escapeHtml(readyLabels.slice(0, 4).join(", "))}</p>` : ""}
        ${missingLabels.length ? `<p><strong>Blocked by missing:</strong> ${escapeHtml(missingLabels.slice(0, 4).join(", "))}</p>` : ""}
        ${paper.abstract_excerpt ? `<p>${escapeHtml(trimText(paper.abstract_excerpt, 280))}</p>` : `<p class="meta-note">This record is currently metadata-only. Open the source to read the full PubMed entry.</p>`}
        ${paper.source_url ? `<p><a href="${escapeAttribute(paper.source_url)}">Open paper</a></p>` : ""}
      `;
      article.addEventListener("click", () => {
        state.selectedEvidence = { kind: "paper", value: paper.paper_id };
        renderSelectedEvidence(state.selectedEvidence, demoCase);
      });
      return article;
    }));
    return;
  }
  const pageSize = 24;
  const start = (state.paperPage - 1) * pageSize;
  const visible = searched.slice(start, start + pageSize);
  if (!searched.length) {
    catalog.innerHTML = `<div class="empty-state">No related papers loaded.</div>`;
    return;
  }
  if (!visible.length) {
    state.paperPage = 1;
    return renderPaperCatalog(catalog, papers, state, demoCase);
  }
  catalog.replaceChildren(...visible.map((paper) => {
    const article = document.createElement("article");
    article.className = "requirement-card";
    const linkedTrials = (paper.linked_trial_ids || []).slice(0, 3);
    const missingLabels = paper.missing_requirement_labels || [];
    const readyLabels = paper.ready_requirement_labels || [];
    const ranking = buildRankingExplanation("paper", paper, demoCase);
    article.innerHTML = `
      <div class="requirement-status status-ok">${escapeHtml(paper.evidence_bucket || "paper")}</div>
      <h3>${escapeHtml(paper.paper_id || "paper")} · ${escapeHtml(paper.title || "")}</h3>
      <p>${escapeHtml(paper.human_summary || "")}</p>
      <div class="kv">
        <div>Journal: ${escapeHtml(paper.journal || "n/a")}</div>
        <div>Year: ${escapeHtml(String(paper.publication_year || "n/a"))}</div>
        <div>Abstract: ${escapeHtml(paper.abstract_excerpt ? "loaded" : "metadata only")}</div>
        <div>Linked trials: ${escapeHtml(linkedTrials.join(", ") || "none")}</div>
      </div>
      <p><strong>Why this rose:</strong> ${escapeHtml(ranking.summary)}</p>
      <div class="kv">
        <div>Rank score: ${escapeHtml(String(ranking.totalScore))}</div>
        <div>Requirement support: ${renderRequirementJumpControl("support", paper.ready_requirement_ids || [], ranking.supportCount, "supported")}</div>
        <div>Requirement blockers: ${renderRequirementJumpControl("blockers", paper.missing_requirement_ids || [], ranking.blockedCount, "blocked")}</div>
        <div>Bitmask contribution: ${escapeHtml(String(ranking.maskScore))}</div>
      </div>
      ${readyLabels.length ? `<p><strong>Supported by:</strong> ${escapeHtml(readyLabels.slice(0, 4).join(", "))}</p>` : ""}
      ${missingLabels.length ? `<p><strong>Blocked by missing:</strong> ${escapeHtml(missingLabels.slice(0, 4).join(", "))}</p>` : ""}
      ${paper.abstract_excerpt ? `<p>${escapeHtml(trimText(paper.abstract_excerpt, 280))}</p>` : `<p class="meta-note">This record is currently metadata-only. Open the source to read the full PubMed entry.</p>`}
      ${paper.source_url ? `<p><a href="${escapeAttribute(paper.source_url)}">Open paper</a></p>` : ""}
    `;
    article.addEventListener("click", () => {
      state.selectedEvidence = { kind: "paper", value: paper.paper_id };
      renderSelectedEvidence(state.selectedEvidence, demoCase);
    });
    return article;
  }));
}

function renderPaperBrowserShell(host, allPapers, filteredPapers, searchedPapers, state, demoCase, catalog, startHerePapers) {
  const abstractCount = allPapers.filter((paper) => paper.abstract_excerpt).length;
  const metadataOnlyCount = allPapers.filter((paper) => paper.metadata_only).length;
  const startHere = buildStartHerePapers(demoCase, startHerePapers);
  const totalPages = Math.max(1, Math.ceil(searchedPapers.length / 24));
  state.paperPage = Math.min(state.paperPage, totalPages);
  const hasFullCorpus = allPapers.length > 0;
  host.innerHTML = `
    <div class="paper-browser-shell">
      <div class="paper-browser-metrics">
        <article class="metric-card compact">
          <div class="metric-label">Start here set</div>
          <div class="metric-value">${escapeHtml(String(startHerePapers.length))}</div>
          <div class="metric-note">Case-ranked papers chosen before you browse the full corpus.</div>
        </article>
        <article class="metric-card compact">
          <div class="metric-label">${escapeHtml(hasFullCorpus ? "All related papers" : "Runtime export mode")}</div>
          <div class="metric-value">${escapeHtml(String(hasFullCorpus ? allPapers.length : startHerePapers.length))}</div>
          <div class="metric-note">${escapeHtml(hasFullCorpus ? "Everything currently connected to this case." : "This shared build only includes the curated case-ranked paper lane, not the full paper corpus.")}</div>
        </article>
        <article class="metric-card compact">
          <div class="metric-label">Abstract-backed</div>
          <div class="metric-value">${escapeHtml(String(abstractCount))}</div>
          <div class="metric-note">Records with local abstract text loaded.</div>
        </article>
        <article class="metric-card compact">
          <div class="metric-label">Metadata only</div>
          <div class="metric-value">${escapeHtml(String(metadataOnlyCount))}</div>
          <div class="metric-note">Title, journal, year, and PubMed link only.</div>
        </article>
        <article class="metric-card compact">
          <div class="metric-label">Visible now</div>
          <div class="metric-value">${escapeHtml(String(searchedPapers.length))}</div>
          <div class="metric-note">After topic and search filtering.</div>
        </article>
      </div>
      <div class="workspace-tabs sub-tabs">
        <button id="paper-view-start" class="workspace-tab${state.paperView === "start_here" ? " active" : ""}" type="button">Start Here (${escapeHtml(String(startHerePapers.length))})</button>
        ${hasFullCorpus ? `<button id="paper-view-full" class="workspace-tab${state.paperView === "full_corpus" ? " active" : ""}" type="button">Full Corpus (${escapeHtml(String(allPapers.length))})</button>` : ""}
      </div>
      <div class="paper-start-here">
        <div class="section-header compact-header">
          <div>
            <h4>Start Here: ${escapeHtml(String(startHerePapers.length))} case-ranked papers</h4>
            <p class="meta-note">This is a short reading lane so a normal person does not have to sift through the full corpus first. These papers were selected for this case because they are GBM or glioma relevant, then ranked toward guidelines and reviews, stage fit, linked trials, local abstract availability, and recency.</p>
          </div>
        </div>
        <div class="paper-start-grid">
          ${startHere.map((paper) => renderStartHerePaperCard(paper)).join("")}
        </div>
      </div>
      <div class="paper-browser-toolbar">
        <label class="paper-search">
          <span class="meta-label">Search papers</span>
          <input id="paper-search-input" type="search" value="${escapeAttribute(state.paperQuery || "")}" placeholder="Search title, journal, trial ID, biomarker, or topic" />
        </label>
        <label class="paper-toggle">
          <input id="paper-abstract-only" type="checkbox" ${state.paperAbstractOnly ? "checked" : ""} />
          <span>Show only papers with local abstract text</span>
        </label>
      </div>
      <div class="paper-browser-caption">
        ${escapeHtml(hasFullCorpus
          ? `Full corpus browser: ${allPapers.length} papers for this case view. Page ${state.paperPage} of ${totalPages}. Showing ${Math.min(24, Math.max(searchedPapers.length - (state.paperPage - 1) * 24, 0))} papers on this page.`
          : `This runtime-only share does not include the full paper corpus. Use the Start Here papers and direct source links for review.`)}
      </div>
      ${hasFullCorpus ? `<div class="paper-pagination">
        <button id="paper-prev-page" class="case-button" type="button" ${state.paperPage <= 1 ? "disabled" : ""}>Previous</button>
        <button id="paper-next-page" class="case-button" type="button" ${state.paperPage >= totalPages ? "disabled" : ""}>Next</button>
      </div>` : ""}
    </div>
  `;

  host.querySelector("#paper-search-input")?.addEventListener("input", (event) => {
    const input = event.target;
    state.paperQuery = input.value;
    state.paperView = hasFullCorpus ? "full_corpus" : "start_here";
    state.paperPage = 1;
    rerenderPreservingSearchPosition(() => {
      renderPaperCatalog(catalog, startHerePapers, state, demoCase);
    }, "#paper-search-input", state.paperQuery, input.selectionStart ?? state.paperQuery.length);
  });
  host.querySelector("#paper-abstract-only")?.addEventListener("change", (event) => {
    state.paperAbstractOnly = event.target.checked;
    state.paperView = hasFullCorpus ? "full_corpus" : "start_here";
    state.paperPage = 1;
    renderPaperCatalog(catalog, startHerePapers, state, demoCase);
  });
  host.querySelector("#paper-prev-page")?.addEventListener("click", () => {
    state.paperPage = Math.max(1, state.paperPage - 1);
    renderPaperCatalog(catalog, startHerePapers, state, demoCase);
  });
  host.querySelector("#paper-next-page")?.addEventListener("click", () => {
    state.paperPage += 1;
    renderPaperCatalog(catalog, startHerePapers, state, demoCase);
  });
  host.querySelectorAll("[data-paper-id]").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedEvidence = { kind: "paper", value: button.dataset.paperId };
      renderSelectedEvidence(state.selectedEvidence, demoCase);
    });
  });
  host.querySelector("#paper-view-start")?.addEventListener("click", () => {
    state.paperView = "start_here";
    renderPaperCatalog(catalog, startHerePapers, state, demoCase);
  });
  host.querySelector("#paper-view-full")?.addEventListener("click", () => {
    state.paperView = "full_corpus";
    renderPaperCatalog(catalog, startHerePapers, state, demoCase);
  });
}

function getCasePaperCorpus(demoCase) {
  if (casePaperCorpusCache.has(demoCase.case_id)) {
    return casePaperCorpusCache.get(demoCase.case_id);
  }
  const requirementBitMap = loadedManifest?.requirement_bit_map || {};
  const readyIds = new Set(demoCase.evidence_ready_ids || []);
  const missingIds = new Set(demoCase.evidence_missing_ids || []);
  const trialDependencyIndex = new Map(
    (demoCase.related_trials || []).map((trial) => [
      trial.trial_id,
      {
        gating_requirement_ids: trial.gating_requirement_ids || [],
        ready_requirement_ids: trial.ready_requirement_ids || [],
        missing_requirement_ids: trial.missing_requirement_ids || [],
        gating_requirement_mask: trial.gating_requirement_mask || 0,
        ready_requirement_labels: trial.ready_requirement_labels || [],
        missing_requirement_labels: trial.missing_requirement_labels || []
      }
    ])
  );
  const requirementLabels = new Map(
    (demoCase.requirements || []).map((requirement) => [requirement.requirement_id, requirement.label || requirement.requirement_id])
  );
  const papers = (loadedCorpora.papers || []).map((paper) =>
    decorateCorpusPaperForCase(
      paper,
      demoCase.bitmask || 0,
      requirementBitMap,
      readyIds,
      missingIds,
      trialDependencyIndex,
      requirementLabels
    )
  );
  casePaperCorpusCache.set(demoCase.case_id, papers);
  return papers;
}

function decorateCorpusPaperForCase(paper, caseBitmask, requirementBitMap, readyIds, missingIds, trialDependencyIndex, requirementLabels) {
  const gatingIds = new Set(paper.gating_requirement_ids || []);
  let gatingMask = Number(paper.gating_requirement_mask || 0);
  (paper.linked_trial_ids || []).forEach((trialId) => {
    const trialDeps = trialDependencyIndex.get(trialId);
    (trialDeps?.gating_requirement_ids || []).forEach((id) => gatingIds.add(id));
    gatingMask |= Number(trialDeps?.gating_requirement_mask || 0);
  });
  if ((paper.linked_mechanism_tags || []).includes("mgmt")) gatingIds.add("mgmt_status_present");
  if ((paper.linked_mechanism_tags || []).includes("idh")) gatingIds.add("idh_status_present");
  if ((paper.linked_mechanism_tags || []).includes("hla")) gatingIds.add("hla_typing_present");
  if ((paper.modality_tags || []).includes("biomarker")) gatingIds.add("ngs_report_present");
  if ((paper.modality_tags || []).includes("cell_therapy") || (paper.modality_tags || []).includes("vaccine")) {
    gatingIds.add("hla_typing_present");
    gatingIds.add("tissue_status_known");
  }
  const text = `${paper.title || ""} ${paper.human_summary || ""} ${paper.abstract_excerpt || ""}`.toLowerCase();
  if (text.includes("performance status") || text.includes("karnofsky") || text.includes("ecog")) gatingIds.add("performance_status_documented");
  if (text.includes("resection") || text.includes("surgical") || text.includes("postoperative")) gatingIds.add("resection_status_known");
  if (text.includes("steroid") || text.includes("dexamethasone")) gatingIds.add("steroid_burden_known");
  if (text.includes("tissue")) gatingIds.add("tissue_status_known");
  if (text.includes("sequencing") || text.includes("genomic") || text.includes("molecular")) gatingIds.add("ngs_report_present");

  const gatingRequirementIds = Array.from(gatingIds).sort();
  gatingMask |= requirementMaskFromIds(gatingRequirementIds, requirementBitMap);
  const missingRequirementIds = gatingRequirementIds.filter((id) => (Number(requirementBitMap[id] || 0) & caseBitmask) !== 0 || missingIds.has(id));
  const readyRequirementIds = gatingRequirementIds.filter((id) => !missingRequirementIds.includes(id) && readyIds.has(id));
  return {
    ...paper,
    gating_requirement_ids: gatingRequirementIds,
    ready_requirement_ids: readyRequirementIds,
    missing_requirement_ids: missingRequirementIds,
    gating_requirement_mask: gatingMask,
    ready_requirement_mask: requirementMaskFromIds(readyRequirementIds, requirementBitMap),
    missing_requirement_mask: requirementMaskFromIds(missingRequirementIds, requirementBitMap),
    gating_requirement_labels: gatingRequirementIds.map((id) => requirementLabels.get(id) || id),
    ready_requirement_labels: readyRequirementIds.map((id) => requirementLabels.get(id) || id),
    missing_requirement_labels: missingRequirementIds.map((id) => requirementLabels.get(id) || id)
  };
}

function requirementMaskFromIds(ids, requirementBitMap) {
  return (ids || []).reduce((mask, id) => mask | Number(requirementBitMap[id] || 0), 0);
}

function buildStartHerePapers(demoCase, filteredPapers) {
  const ranked = filteredPapers
    .slice()
    .sort((left, right) => scorePaperForCase(right, demoCase) - scorePaperForCase(left, demoCase));
  return ranked.slice(0, 6);
}

function fullCorpusPapersLabel() {
  const count = loadedCorpora.papers.length || 0;
  return count ? `${count} papers in full corpus` : "runtime-only paper export";
}

function rerenderPreservingSearchPosition(renderFn, inputSelector, value, cursorPosition) {
  const scrollY = window.scrollY;
  renderFn();
  window.requestAnimationFrame(() => {
    window.scrollTo({ top: scrollY });
    const nextInput = document.querySelector(inputSelector);
    if (!nextInput) {
      return;
    }
    nextInput.focus({ preventScroll: true });
    nextInput.value = value;
    const nextCursor = Math.min(cursorPosition ?? value.length, nextInput.value.length);
    try {
      nextInput.setSelectionRange(nextCursor, nextCursor);
    } catch {
      // Some search input implementations may reject selection APIs.
    }
  });
}

function scorePaperForCase(paper, demoCase) {
  let score = maskSupportScore(paper, demoCase, 18, 28);
  if (paper.evidence_bucket === "guideline") score += 100;
  if (paper.evidence_bucket === "review") score += 80;
  if (paper.evidence_bucket === "trial_publication") score += 55;
  if (paper.abstract_excerpt) score += 12;
  if ((paper.linked_trial_ids || []).length) score += 8;
  if ((paper.stage_tags || []).includes("newly_diagnosed") && String(demoCase.title || "").toLowerCase().includes("newly diagnosed")) score += 15;
  if ((paper.modality_tags || []).includes("radiation")) score += 6;
  return score + Number(paper.publication_year || 0) / 10000;
}

function scoreTrialForCase(trial, demoCase) {
  let score = Number(trial.review_priority_score || 0);
  score += maskSupportScore(trial, demoCase, 22, 35);
  if (trial.status === "candidate_for_review") score += 50;
  if (trial.status === "needs_more_evidence") score += 20;
  if (trial.status === "historical_signal") score -= 20;
  return score;
}

function getMaskMetrics(item, demoCase) {
  const caseBitmask = Number(demoCase.bitmask || 0);
  const gatingMask = Number(item.gating_requirement_mask || 0);
  const blockedMask = gatingMask & caseBitmask;
  const supportedMask = gatingMask & (~caseBitmask);
  return {
    gatingMask,
    blockedMask,
    supportedMask,
    blockedCount: popcount(blockedMask),
    supportCount: popcount(supportedMask)
  };
}

function buildRankingExplanation(kind, item, demoCase) {
  const metrics = getMaskMetrics(item, demoCase);
  const maskScore = kind === "trial"
    ? maskSupportScore(item, demoCase, 22, 35)
    : maskSupportScore(item, demoCase, 18, 28);
  const signals = [];
  if (metrics.supportCount) {
    signals.push(`${metrics.supportCount} requirement${metrics.supportCount === 1 ? "" : "s"} already supported`);
  }
  if (metrics.blockedCount) {
    signals.push(`${metrics.blockedCount} blocker${metrics.blockedCount === 1 ? "" : "s"} from missing evidence`);
  }
  if (kind === "trial") {
    if (item.status === "candidate_for_review") {
      signals.push("it is currently one of the strongest direct fits");
    } else if (item.status === "needs_more_evidence") {
      signals.push("it looks relevant but still needs more case data");
    } else if (item.status === "historical_signal") {
      signals.push("it is mainly useful as historical or negative signal");
    }
    if (Number(item.review_priority_score || 0) > 0) {
      signals.push(`the trial logic gave it a base priority of ${Number(item.review_priority_score || 0)}`);
    }
  } else {
    if (item.evidence_bucket === "guideline") {
      signals.push("guideline evidence is pushed toward the top");
    } else if (item.evidence_bucket === "review") {
      signals.push("broad review evidence is favored for orientation");
    } else if (item.evidence_bucket === "trial_publication") {
      signals.push("it directly reports on a trial or trial-like study");
    }
    if ((item.linked_trial_ids || []).length) {
      signals.push(`it connects to ${item.linked_trial_ids.length} linked trial${item.linked_trial_ids.length === 1 ? "" : "s"}`);
    }
    if (item.abstract_excerpt) {
      signals.push("local abstract text is available");
    }
  }
  const totalScore = kind === "trial" ? scoreTrialForCase(item, demoCase) : scorePaperForCase(item, demoCase);
  return {
    totalScore,
    maskScore,
    supportCount: metrics.supportCount,
    blockedCount: metrics.blockedCount,
    summary: signals.length ? signals.join("; ") : "ranking is mostly driven by general relevance rather than requirement gating"
  };
}

function maskSupportScore(item, demoCase, supportWeight, blockedWeight) {
  const caseBitmask = Number(demoCase.bitmask || 0);
  const gatingMask = Number(item.gating_requirement_mask || 0);
  if (!gatingMask) {
    return 0;
  }
  const blockedMask = gatingMask & caseBitmask;
  const supportedMask = gatingMask & (~caseBitmask);
  return popcount(supportedMask) * supportWeight - popcount(blockedMask) * blockedWeight;
}

function popcount(value) {
  let count = 0;
  let current = value >>> 0;
  while (current) {
    count += current & 1;
    current >>>= 1;
  }
  return count;
}

function renderStartHerePaperCard(paper) {
  const demoCase = document.getElementById("case-detail")?.__demoCase;
  const ranking = demoCase ? buildRankingExplanation("paper", paper, demoCase) : null;
  return `
    <article class="source-card start-here-card" data-paper-id="${escapeAttribute(paper.paper_id)}">
      <div class="meta-label">${escapeHtml(paper.evidence_bucket || "paper")}</div>
      <h4>${escapeHtml(paper.title || paper.paper_id || "paper")}</h4>
      <p>${escapeHtml(paper.human_summary || "")}</p>
      <div class="meta-note">${escapeHtml(paper.abstract_excerpt ? "Abstract loaded locally" : "Metadata only")} · ${escapeHtml(String(paper.publication_year || "n/a"))}</div>
      ${ranking ? `<p class="meta-note"><strong>Why this rose:</strong> ${escapeHtml(ranking.summary)}</p>` : ""}
      ${ranking ? `<p class="meta-note">Jump to: ${renderRequirementJumpControl("support", paper.ready_requirement_ids || [], ranking.supportCount, "supported")} · ${renderRequirementJumpControl("blockers", paper.missing_requirement_ids || [], ranking.blockedCount, "blocked")}</p>` : ""}
      ${paper.source_url ? `<p><a href="${escapeAttribute(paper.source_url)}" target="_blank" rel="noreferrer">Open paper</a></p>` : ""}
    </article>
  `;
}

function filterPapersForBrowser(papers, state) {
  const query = (state.paperQuery || "").trim().toLowerCase();
  return papers.filter((paper) => {
    if (state.paperAbstractOnly && !paper.abstract_excerpt) {
      return false;
    }
    if (!query) {
      return true;
    }
    const haystack = [
      paper.title,
      paper.paper_id,
      paper.journal,
      paper.human_summary,
      (paper.linked_trial_ids || []).join(" "),
      (paper.modality_tags || []).join(" "),
      (paper.stage_tags || []).join(" "),
      (paper.linked_mechanism_tags || []).join(" ")
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return haystack.includes(query);
  });
}

function renderDatasetCatalog(catalog, datasets, state, demoCase) {
  if (!catalog) {
    return;
  }
  const visible = filterEvidenceItems(datasets, state, "dataset");
  if (!visible.length) {
    catalog.innerHTML = `<div class="empty-state">No related datasets loaded.</div>`;
    return;
  }
  catalog.replaceChildren(...visible.map((dataset) => {
    const article = document.createElement("article");
    article.className = "requirement-card";
    article.innerHTML = `
      <div class="requirement-status status-ok">${escapeHtml(dataset.dataset_type || "dataset")}</div>
      <h3>${escapeHtml(dataset.dataset_id || "dataset")} · ${escapeHtml(dataset.title || "")}</h3>
      <p>${escapeHtml(dataset.human_summary || "")}</p>
      <div class="kv">
        <div>Access: ${escapeHtml(dataset.access || "n/a")}</div>
        <div>Type: ${escapeHtml(dataset.dataset_type || "n/a")}</div>
      </div>
      ${dataset.url ? `<p><a href="${escapeAttribute(dataset.url)}">Open dataset</a></p>` : ""}
    `;
    article.addEventListener("click", () => {
      state.selectedEvidence = { kind: "dataset", value: dataset.dataset_id };
      renderSelectedEvidence(state.selectedEvidence, demoCase);
    });
    return article;
  }));
}

function statusClassForTrial(status) {
  if (status === "candidate_for_review") return "status-ok";
  if (status === "needs_more_evidence") return "status-missing";
  return "";
}

function formatComparisons(comparisons) {
  if (!comparisons || !comparisons.length) {
    return "No normalized comparisons.";
  }
  return comparisons
    .slice(0, 4)
    .map((item) => `${item.field}: ${item.observed} vs ${item.expected} (${item.matched ? "match" : "mismatch"})`)
    .join(" | ");
}

function wireGraphModeControls(container, state) {
  container.querySelector("#graph-mode-patient")?.addEventListener("click", () => {
    state.mode = "patient";
    syncGraphModeButtons(container, state);
    renderEvidenceView(container, currentCaseFromContainer(container), state);
  });
  container.querySelector("#graph-mode-research")?.addEventListener("click", () => {
    state.mode = "research";
    syncGraphModeButtons(container, state);
    renderEvidenceView(container, currentCaseFromContainer(container), state);
  });
  container.querySelector("#graph-reset")?.addEventListener("click", () => {
    state.mode = "patient";
    state.concept = null;
    state.trialStatus = "all";
    syncGraphModeButtons(container, state);
    renderEvidenceView(container, currentCaseFromContainer(container), state);
  });
}

function wireWorkspaceTabs(container, state, demoCase) {
  container.querySelectorAll(".workspace-tab").forEach((button) => {
    button.addEventListener("click", () => {
      state.activeTab = button.dataset.tab || "overview";
      syncWorkspaceTabs(container, state);
      renderEvidenceView(container, demoCase, state);
    });
  });
}

function currentCaseFromContainer(container) {
  return container.__demoCase;
}

function wireConceptFilters(row, demoCase, state) {
  if (!row) {
    return;
  }
  row.innerHTML = "";
  const concepts = (demoCase.evidence_graph?.top_concepts || []).slice(0, 12);
  const allButton = document.createElement("button");
  allButton.className = "case-button";
  allButton.type = "button";
  allButton.dataset.concept = "";
  allButton.textContent = "Show all topics";
  allButton.addEventListener("click", () => {
    state.concept = null;
    syncConceptButtons(row, state);
    renderEvidenceView(row.closest(".case-detail"), demoCase, state);
  });
  row.appendChild(allButton);
  concepts.forEach((concept) => {
    const button = document.createElement("button");
    button.className = "case-button";
    button.type = "button";
    button.dataset.concept = concept;
    button.textContent = formatConceptLabel(concept);
    button.addEventListener("click", () => {
      state.concept = state.concept === concept ? null : concept;
      syncConceptButtons(row, state);
      renderEvidenceView(row.closest(".case-detail"), demoCase, state);
    });
    row.appendChild(button);
  });
  syncConceptButtons(row, state);
}

function syncConceptButtons(row, state) {
  row.querySelectorAll("button").forEach((button) => {
    const concept = button.dataset.concept || "";
    const active = (!state.concept && concept === "") || state.concept === concept;
    button.classList.toggle("active", active);
  });
}

function syncTrialStatusButtons(row, state) {
  row.querySelectorAll("button").forEach((button, index) => {
    const value = ["all", "candidate_for_review", "needs_more_evidence", "unlikely_fit_now", "historical_signal"][index];
    button.classList.toggle("active", value === state.trialStatus);
  });
}

function syncGraphModeButtons(container, state) {
  container.querySelector("#graph-mode-patient")?.classList.toggle("active", state.mode === "patient");
  container.querySelector("#graph-mode-research")?.classList.toggle("active", state.mode === "research");
}

function syncWorkspaceTabs(container, state) {
  container.querySelectorAll(".workspace-tab").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === state.activeTab);
  });
  container.querySelectorAll(".workspace-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `workspace-${state.activeTab}`);
  });
}

function filterEvidenceItems(items, state, kind) {
  let visible = items;
  if (kind === "trial" && state.trialStatus !== "all") {
    visible = visible.filter((item) => item.status === state.trialStatus);
  }
  if (state.concept) {
    visible = visible.filter((item) => (item.concept_tags || []).includes(state.concept));
  }
  return visible;
}

function renderGraphFocus(titleEl, descEl, state) {
  if (!titleEl || !descEl) {
    return;
  }
  if (state.concept) {
    titleEl.textContent = formatConceptLabel(state.concept);
    descEl.textContent = state.mode === "research"
      ? "Research view centered on the selected concept across trials, papers, and datasets."
      : "Patient view filtered to the selected concept.";
    return;
  }
  titleEl.textContent = state.mode === "research" ? "Research overview" : "Patient overview";
  descEl.textContent = state.mode === "research"
    ? "Showing concept-centered evidence clusters across the case corpus."
    : "Showing the patient and the strongest related concepts and evidence.";
}

function renderSelectedEvidence(selection, demoCase) {
  const host = document.getElementById("evidence-detail-content");
  if (!host) {
    return;
  }
  if (!selection) {
    host.innerHTML = `
      <div class="evidence-detail-title">${escapeHtml(demoCase.title)}</div>
      <div class="evidence-detail-meta">${escapeHtml(friendlyCaseResult(demoCase))}</div>
      <div>${escapeHtml(buildPatientFocusSummary(demoCase))}</div>
      <ul class="evidence-detail-list">
        ${buildDiscussNowLines(demoCase).slice(0, 3).map((line) => `<li>${escapeHtml(line)}</li>`).join("")}
      </ul>
    `;
    return;
  }
  if (selection.kind === "concept") {
    const concept = selection.value;
    const trials = (demoCase.related_trials || []).filter((item) => (item.concept_tags || []).includes(concept));
    const papers = (demoCase.related_papers || []).filter((item) => (item.concept_tags || []).includes(concept));
    const datasets = (demoCase.related_datasets || []).filter((item) => (item.concept_tags || []).includes(concept));
    host.innerHTML = `
      <div class="evidence-detail-title">${escapeHtml(formatConceptLabel(concept))}</div>
      <div class="evidence-detail-meta">Concept view</div>
      <div>This concept is connected to ${escapeHtml(String(trials.length))} trials, ${escapeHtml(String(papers.length))} papers, and ${escapeHtml(String(datasets.length))} datasets in this case.</div>
      <ul class="evidence-detail-list">
        ${trials.slice(0, 3).map((item) => `<li>${escapeHtml(item.title)}</li>`).join("")}
      </ul>
    `;
    return;
  }
  if (selection.kind === "trial") {
    const item = (demoCase.related_trials || []).find((trial) => trial.trial_id === selection.value);
    if (!item) return;
    const ranking = buildRankingExplanation("trial", item, demoCase);
    host.innerHTML = `
      <div class="evidence-detail-title">${escapeHtml(item.title)}</div>
      <div class="evidence-detail-meta">${escapeHtml(item.trial_id)} · ${escapeHtml(item.status || "related")} · ${escapeHtml(item.recruitment_status || "n/a")}</div>
      <div>${escapeHtml(item.human_summary || item.summary || "")}</div>
      <ul class="evidence-detail-list">
        <li><strong>Why this rose:</strong> ${escapeHtml(ranking.summary)}</li>
        <li>Rank score: ${escapeHtml(String(ranking.totalScore))} total, with ${escapeHtml(String(ranking.maskScore))} coming from requirement-bit support.</li>
        <li>Requirement support: ${renderRequirementJumpControl("support", item.ready_requirement_ids || [], ranking.supportCount, "supported")} and ${renderRequirementJumpControl("blockers", item.missing_requirement_ids || [], ranking.blockedCount, "blocked")}.</li>
        ${(item.ready_requirement_labels || []).length ? `<li>Supported by: ${escapeHtml((item.ready_requirement_labels || []).join(", "))}</li>` : ""}
        ${(item.missing_requirement_labels || []).length ? `<li>Blocked by missing: ${escapeHtml((item.missing_requirement_labels || []).join(", "))}</li>` : ""}
        ${(item.reasons || []).map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}
      </ul>
      ${item.source_url ? `<p><a href="${escapeAttribute(item.source_url)}">Open trial source</a></p>` : ""}
    `;
    return;
  }
  if (selection.kind === "paper") {
    const item = getCasePaperCorpus(demoCase).find((paper) => paper.paper_id === selection.value);
    if (!item) return;
    const ranking = buildRankingExplanation("paper", item, demoCase);
    host.innerHTML = `
      <div class="evidence-detail-title">${escapeHtml(item.title)}</div>
      <div class="evidence-detail-meta">${escapeHtml(item.paper_id)} · ${escapeHtml(item.evidence_bucket || "paper")} · ${escapeHtml(String(item.publication_year || "n/a"))}</div>
      <div>${escapeHtml(item.human_summary || "")}</div>
      <ul class="evidence-detail-list">
        <li><strong>Why this rose:</strong> ${escapeHtml(ranking.summary)}</li>
        <li>Rank score: ${escapeHtml(String(ranking.totalScore))} total, with ${escapeHtml(String(ranking.maskScore))} coming from requirement-bit support.</li>
        <li>Requirement support: ${renderRequirementJumpControl("support", item.ready_requirement_ids || [], ranking.supportCount, "supported")} and ${renderRequirementJumpControl("blockers", item.missing_requirement_ids || [], ranking.blockedCount, "blocked")}.</li>
        <li>Local text: ${escapeHtml(item.abstract_excerpt ? "abstract loaded" : "metadata only")}</li>
        <li>Linked trials: ${escapeHtml((item.linked_trial_ids || []).join(", ") || "none")}</li>
        ${(item.ready_requirement_labels || []).length ? `<li>Supported by: ${escapeHtml((item.ready_requirement_labels || []).join(", "))}</li>` : ""}
        ${(item.missing_requirement_labels || []).length ? `<li>Blocked by missing: ${escapeHtml((item.missing_requirement_labels || []).join(", "))}</li>` : ""}
      </ul>
      ${item.abstract_excerpt ? `<p>${escapeHtml(trimText(item.abstract_excerpt, 600))}</p>` : ""}
      ${item.source_url ? `<p><a href="${escapeAttribute(item.source_url)}">Open paper source</a></p>` : ""}
    `;
    return;
  }
  if (selection.kind === "dataset") {
    const item = (demoCase.related_datasets || []).find((dataset) => dataset.dataset_id === selection.value);
    if (!item) return;
    host.innerHTML = `
      <div class="evidence-detail-title">${escapeHtml(item.title)}</div>
      <div class="evidence-detail-meta">${escapeHtml(item.dataset_id)} · ${escapeHtml(item.dataset_type || "dataset")} · ${escapeHtml(item.access || "n/a")}</div>
      <div>${escapeHtml(item.human_summary || "")}</div>
      <ul class="evidence-detail-list">
        <li>Useful for: ${escapeHtml((item.concept_tags || []).join(", ") || "general GBM context")}</li>
      </ul>
      ${item.url ? `<p><a href="${escapeAttribute(item.url)}">Open dataset source</a></p>` : ""}
    `;
  }
}

function renderRequirementJumpControl(label, requirementIds, count, mode) {
  const total = Number(count || 0);
  if (!total) {
    return escapeHtml(`0 ${label}`);
  }
  return `<button type="button" class="inline-action" data-requirement-jump="${escapeAttribute(mode)}" data-requirement-ids="${escapeAttribute((requirementIds || []).join(","))}">${escapeHtml(String(total))} ${escapeHtml(label)}</button>`;
}

function requirementDomId(requirementId) {
  return `requirement-${String(requirementId || "unknown").replace(/[^a-z0-9_-]+/gi, "-")}`;
}

function wireRequirementJumpLinks(container) {
  if (container.__requirementJumpBound) {
    return;
  }
  container.__requirementJumpBound = true;
  container.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-requirement-jump]");
    if (!trigger || !container.contains(trigger)) {
      return;
    }
    event.preventDefault();
    const ids = String(trigger.dataset.requirementIds || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    jumpToRequirements(container, ids);
  });
}

function jumpToRequirements(container, requirementIds) {
  const state = container.__workspaceState;
  if (state) {
    state.activeTab = "overview";
    syncWorkspaceTabs(container, state);
  }
  const uniqueIds = Array.from(new Set(requirementIds || []));
  const targets = uniqueIds
    .map((id) => container.querySelector(`#${CSS.escape(requirementDomId(id))}`))
    .filter(Boolean);
  const firstTarget = targets[0] || container.querySelector("#requirement-grid");
  if (!firstTarget) {
    return;
  }
  firstTarget.scrollIntoView({ behavior: "smooth", block: "center" });
  targets.forEach((element) => {
    element.classList.add("requirement-card-highlight");
    window.setTimeout(() => {
      element.classList.remove("requirement-card-highlight");
    }, 1800);
  });
}

function renderEvidenceGraph(host, demoCase, state, onSelect) {
  if (!host) {
    return;
  }
  const concepts = (demoCase.evidence_graph?.top_concepts || []).slice(0, 10);
  const graphTrials = filterEvidenceItems(demoCase.related_trials || [], state, "trial")
    .filter((item) => state.mode === "research" || item.status !== "historical_signal")
    .slice(0, 8);
  const papers = filterEvidenceItems(demoCase.related_papers || [], state, "paper").slice(0, 6);
  const datasets = filterEvidenceItems(demoCase.related_datasets || [], state, "dataset").slice(0, 5);
  const width = host.clientWidth || 880;
  const height = 480;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("width", "100%");
  svg.setAttribute("height", String(height));

  if (!concepts.length) {
    host.innerHTML = `<div class="graph-empty">No graph concepts available for this case.</div>`;
    return;
  }

  const patientNode = { id: "patient", label: demoCase.title, type: "patient", x: 110, y: height / 2 };
  const conceptNodes = concepts.map((concept, index) => ({
    id: `concept:${concept}`,
    label: concept,
    type: "concept",
    concept,
    x: state.mode === "research" ? width / 2 : width * 0.42,
    y: 70 + index * ((height - 140) / Math.max(1, concepts.length - 1))
  }));
  const trialNodes = graphTrials.map((trial, index) => ({
    id: `trial:${trial.trial_id}`,
    label: trial.trial_id,
    type: "trial",
    trial,
    x: width * 0.74,
    y: 60 + index * 56
  }));
  const paperNodes = papers.map((paper, index) => ({
    id: `paper:${paper.paper_id}`,
    label: paper.paper_id.replace("PMID:", "PMID "),
    type: "paper",
    paper,
    x: width * 0.74,
    y: 300 + index * 42
  }));
  const datasetNodes = datasets.map((dataset, index) => ({
    id: `dataset:${dataset.dataset_id}`,
    label: dataset.dataset_id,
    type: "dataset",
    dataset,
    x: state.mode === "research" ? width * 0.18 : width * 0.58,
    y: 300 + index * 42
  }));

  const nodes = [patientNode, ...conceptNodes, ...trialNodes, ...paperNodes, ...datasetNodes];
  const conceptMap = new Map(conceptNodes.map((node) => [node.concept, node]));
  const edges = [];

  if (state.mode === "patient") {
    conceptNodes.forEach((conceptNode) => edges.push([patientNode, conceptNode]));
  }
  trialNodes.forEach((trialNode) => {
    (trialNode.trial.concept_tags || []).forEach((tag) => {
      const conceptNode = conceptMap.get(tag);
      if (conceptNode) {
        edges.push([conceptNode, trialNode]);
      }
    });
  });
  paperNodes.forEach((paperNode) => {
    (paperNode.paper.concept_tags || []).forEach((tag) => {
      const conceptNode = conceptMap.get(tag);
      if (conceptNode) {
        edges.push([conceptNode, paperNode]);
      }
    });
  });
  datasetNodes.forEach((datasetNode) => {
    (datasetNode.dataset.concept_tags || []).forEach((tag) => {
      const conceptNode = conceptMap.get(tag);
      if (conceptNode) {
        edges.push([conceptNode, datasetNode]);
      }
    });
  });

  edges.forEach(([from, to]) => {
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("class", "graph-edge");
    line.setAttribute("x1", String(from.x));
    line.setAttribute("y1", String(from.y));
    line.setAttribute("x2", String(to.x));
    line.setAttribute("y2", String(to.y));
    svg.appendChild(line);
  });

  nodes.forEach((node) => {
    const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
    group.setAttribute("class", `graph-node${isGraphNodeActive(node, state) ? " active" : ""}`);
    group.setAttribute("transform", `translate(${node.x}, ${node.y})`);
    if (node.type === "concept") {
      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("r", "16");
      circle.setAttribute("fill", "#0f7c7a");
      group.appendChild(circle);
    } else {
      const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      rect.setAttribute("x", "-44");
      rect.setAttribute("y", "-16");
      rect.setAttribute("rx", "10");
      rect.setAttribute("width", "88");
      rect.setAttribute("height", "32");
      rect.setAttribute("fill", graphNodeFill(node));
      group.appendChild(rect);
    }
    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("text-anchor", "middle");
    text.setAttribute("dominant-baseline", "middle");
    text.textContent = graphNodeLabel(node);
    group.appendChild(text);
    if (node.type === "concept") {
      group.addEventListener("click", () => onSelect("concept", node.concept));
    } else if (node.type === "trial") {
      group.addEventListener("click", () => onSelect("trial", node.trial.trial_id));
    } else if (node.type === "paper") {
      group.addEventListener("click", () => onSelect("paper", node.paper.paper_id));
    } else if (node.type === "dataset") {
      group.addEventListener("click", () => onSelect("dataset", node.dataset.dataset_id));
    }
    svg.appendChild(group);
  });

  host.replaceChildren(svg);
}

function graphNodeFill(node) {
  if (node.type === "patient") return "#17272a";
  if (node.type === "trial") {
    if (node.trial.status === "candidate_for_review") return "#2d6cdf";
    if (node.trial.status === "needs_more_evidence") return "#c9861a";
    return "#8b97a6";
  }
  if (node.type === "paper") return "#4466bb";
  if (node.type === "dataset") return "#14806a";
  return "#0f7c7a";
}

function graphNodeLabel(node) {
  if (node.type === "concept") return formatConceptLabel(node.label);
  if (node.type === "patient") return "Patient";
  return node.label.length > 16 ? `${node.label.slice(0, 15)}…` : node.label;
}

function isGraphNodeActive(node, state) {
  return node.type === "concept" && state.concept === node.concept;
}

async function renderArtifactPreview(artifact) {
  const title = document.getElementById("artifact-preview-title");
  const description = document.getElementById("artifact-preview-description");
  const content = document.getElementById("artifact-preview-content");
  const link = document.getElementById("artifact-preview-link");

  setText("artifact-preview-title", artifact.label);
  description.textContent = artifact.description || "";
  link.href = artifact.path;
  link.hidden = false;

  try {
    const response = await fetch(artifact.path);
    if (!response.ok) {
      throw new Error(`Unable to load ${artifact.path}`);
    }
    const raw = await response.text();
    content.replaceChildren(renderArtifactPreviewContent(artifact.path, raw));
  } catch (error) {
    title.textContent = artifact.label;
    content.replaceChildren(renderRawPreview(`Unable to preview artifact.\n\n${error.message}`));
  }
}

function renderArtifactPreviewContent(path, raw) {
  const lower = path.toLowerCase();
  if (lower.endsWith(".json")) {
    try {
      return renderJsonArtifactPreview(path, JSON.parse(raw));
    } catch {
      return renderRawPreview(raw.slice(0, 12000));
    }
  }
  if (lower.endsWith(".md") || lower.endsWith(".rego") || lower.endsWith(".rs")) {
    return renderRawPreview(raw.slice(0, 12000));
  }
  return renderRawPreview(`Preview unavailable for this file type.\n\nPath: ${path}`);
}

function formatConceptLabel(concept) {
  const labels = {
    newly_diagnosed: "Newly diagnosed",
    post_surgery: "After surgery",
    recurrent: "Recurrent disease",
    radiation: "Radiation",
    mgmt: "MGMT biomarker",
    idh: "IDH biomarker",
    performance_status_good: "Strong daily function",
    steroid_stability: "Low / stable steroids",
    adult_patient: "Adult patient",
    imaging: "Imaging",
    biomarker: "Biomarkers",
    immunotherapy: "Immunotherapy",
    pdl1: "PD-L1",
    temozolomide: "Temozolomide",
    ttfields: "Tumor Treating Fields",
    cell_therapy: "Cell therapy",
    vaccine: "Vaccine"
  };
  return labels[concept] || concept.replaceAll("_", " ");
}

function renderJsonArtifactPreview(path, data) {
  const lower = path.toLowerCase();
  if (lower.endsWith("demo_manifest.json")) {
    return renderManifestPreview(data);
  }
  if (lower.endsWith("pearl.json")) {
    return renderPearlPreview(data);
  }
  if (lower.endsWith("navigator_report.json")) {
    return renderNavigatorReportPreview(data);
  }
  if (lower.endsWith("evidence_graph.json")) {
    return renderEvidenceGraphPreview(data);
  }
  if (lower.endsWith("trial_corpus.generated.json") || lower.endsWith("trial_options.generated.json")) {
    return renderTrialCorpusPreview(data);
  }
  if (lower.endsWith("literature_corpus.generated.json")) {
    return renderLiteratureCorpusPreview(data);
  }
  return renderRawPreview(JSON.stringify(data, null, 2).slice(0, 12000));
}

function renderManifestPreview(data) {
  return renderPreviewLayout([
    renderSummaryGrid([
      ["Title", data.title || "n/a"],
      ["Cases", String((data.cases || []).length)],
      ["Artifacts", String((data.artifacts || []).length)],
      ["Sources", String((data.sources || []).length)]
    ]),
    renderListSection("Cases", (data.cases || []).slice(0, 6).map((item) => ({
      title: item.title,
      meta: item.result,
      copy: `${item.summary || ""} Related trials: ${item.trial_counts?.all_related ?? 0}.`
    })))
  ]);
}

function renderPearlPreview(data) {
  return renderPreviewLayout([
    renderSummaryGrid([
      ["Program", data.program_id || "n/a"],
      ["Evidence", String((data.evidence_requirements || []).length)],
      ["Care Paths", String((data.care_pathways || []).length)],
      ["Trials", String((data.trial_corpus || data.trial_options || []).length)],
      ["Papers", String((data.literature_corpus || []).length)],
      ["Datasets", String((data.dataset_catalog || []).length)]
    ]),
    renderListSection("Evidence Requirements", (data.evidence_requirements || []).slice(0, 6).map((item) => ({
      title: item.label,
      meta: item.requirement_id,
      copy: item.why_it_matters
    })))
  ]);
}

function renderNavigatorReportPreview(data) {
  return renderPreviewLayout([
    renderSummaryGrid([
      ["Cases", String(data.length || 0)],
      ["Candidates", String(data.reduce((sum, item) => sum + (item.summary?.trial_candidates || 0), 0))],
      ["Needs Evidence", String(data.reduce((sum, item) => sum + (item.summary?.trials_needing_more_evidence || 0), 0))]
    ]),
    renderListSection("Case Outcomes", data.slice(0, 6).map((item) => ({
      title: item.case_title,
      meta: `Ready ${item.summary?.ready ?? 0} / Missing ${item.summary?.missing ?? 0}`,
      copy: `Care paths: ${item.summary?.recommended_care_pathways ?? 0}. Trial candidates: ${item.summary?.trial_candidates ?? 0}.`
    })))
  ]);
}

function renderEvidenceGraphPreview(data) {
  const concepts = (data.nodes || []).filter((node) => node.type === "concept").slice(0, 8);
  return renderPreviewLayout([
    renderSummaryGrid([
      ["Nodes", String((data.nodes || []).length)],
      ["Edges", String((data.edges || []).length)],
      ["Concepts", String((data.nodes || []).filter((node) => node.type === "concept").length)]
    ]),
    renderListSection("Top Concepts", concepts.map((node) => ({
      title: node.label,
      meta: node.type,
      copy: `Graph concept node: ${node.id}`
    })))
  ]);
}

function renderTrialCorpusPreview(data) {
  return renderPreviewLayout([
    renderSummaryGrid([
      ["Trials", String(data.length || 0)],
      ["Actionable", String(data.filter((item) => item.actionability_bucket === "actionable_now").length)],
      ["Historical", String(data.filter((item) => item.actionability_bucket === "historical_signal").length)]
    ]),
    renderListSection("Top Trials", data.slice(0, 8).map((item) => ({
      title: `${item.trial_id} · ${item.title}`,
      meta: `${item.recruitment_status} · ${item.phase || "NA"}`,
      copy: item.human_summary || item.summary || ""
    })))
  ]);
}

function renderLiteratureCorpusPreview(data) {
  return renderPreviewLayout([
    renderSummaryGrid([
      ["Papers", String(data.length || 0)],
      ["Reviews", String(data.filter((item) => item.evidence_bucket === "review").length)],
      ["Guidelines", String(data.filter((item) => item.evidence_bucket === "guideline").length)]
    ]),
    renderListSection("Top Papers", data.slice(0, 8).map((item) => ({
      title: `${item.paper_id} · ${item.title}`,
      meta: `${item.evidence_bucket} · ${item.publication_year || "n/a"}`,
      copy: item.human_summary || ""
    })))
  ]);
}

function renderPreviewLayout(children) {
  const wrapper = document.createElement("div");
  children.forEach((child) => wrapper.appendChild(child));
  return wrapper;
}

function renderSummaryGrid(items) {
  const grid = document.createElement("div");
  grid.className = "artifact-summary-grid";
  items.forEach(([label, value]) => {
    const card = document.createElement("div");
    card.className = "artifact-summary-card";
    card.innerHTML = `
      <div class="artifact-summary-label">${escapeHtml(label)}</div>
      <div class="artifact-summary-value">${escapeHtml(value)}</div>
    `;
    grid.appendChild(card);
  });
  return grid;
}

function renderListSection(title, items) {
  const section = document.createElement("section");
  section.className = "artifact-section";
  const heading = document.createElement("h4");
  heading.textContent = title;
  section.appendChild(heading);
  const list = document.createElement("div");
  list.className = "artifact-list";
  items.forEach((item) => {
    const card = document.createElement("article");
    card.className = "artifact-list-card";
    card.innerHTML = `
      <div class="artifact-list-title">${escapeHtml(item.title || "")}</div>
      <div class="artifact-list-meta">${escapeHtml(item.meta || "")}</div>
      <div class="artifact-list-copy">${escapeHtml(item.copy || "")}</div>
    `;
    list.appendChild(card);
  });
  section.appendChild(list);
  return section;
}

function renderRawPreview(text) {
  const pre = document.createElement("pre");
  pre.textContent = text;
  return pre;
}

function renderList(id, items) {
  const list = document.getElementById(id);
  list.replaceChildren(...items.map((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    return li;
  }));
}

function setText(id, value) {
  document.getElementById(id).textContent = value || "";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeAttribute(value) {
  return escapeHtml(value);
}

function trimText(value, limit) {
  const text = String(value || "").trim();
  if (text.length <= limit) {
    return text;
  }
  return `${text.slice(0, Math.max(0, limit - 1)).trimEnd()}…`;
}

main().catch((error) => {
  document.body.innerHTML = `<main class="main-content"><section class="content-card"><h1>Unable to load demo</h1><p>${escapeHtml(error.message)}</p></section></main>`;
});
