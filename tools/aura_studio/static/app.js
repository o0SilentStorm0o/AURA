const state = {
  health: null,
  presets: {},
  lastResult: null,
};

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || `Request failed: ${response.status}`);
  }
  return payload;
}

function setLog(message) {
  $("runLog").textContent = message;
}

function splitList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function currentProfile() {
  return {
    appCategory: $("appCategory").value,
    dataSensitivity: $("dataSensitivity").value,
    releaseStage: $("releaseStage").value,
    distribution: "google_play",
    authFlow: $("authFlow").checked,
    payments: $("payments").checked,
    webviewUsageExpected: $("webviewUsageExpected").checked,
    externalIntegrationsExpected: $("externalIntegrationsExpected").checked,
    allowedCleartextDomains: splitList($("allowedCleartextDomains").value),
    knownExportedComponents: splitList($("knownExportedComponents").value),
    acceptedRisks: [],
  };
}

function applyProfile(profile) {
  $("appCategory").value = profile.appCategory || "ecommerce";
  $("dataSensitivity").value = profile.dataSensitivity || "medium";
  $("releaseStage").value = profile.releaseStage || "production_candidate";
  $("authFlow").checked = Boolean(profile.authFlow);
  $("payments").checked = Boolean(profile.payments);
  $("webviewUsageExpected").checked = profile.webviewUsageExpected !== false;
  $("externalIntegrationsExpected").checked = profile.externalIntegrationsExpected !== false;
  $("allowedCleartextDomains").value = (profile.allowedCleartextDomains || []).join(", ");
  $("knownExportedComponents").value = (profile.knownExportedComponents || []).join(", ");
}

function statusDot(ok, warn = false) {
  if (ok) return "dot";
  if (warn) return "dot warn";
  return "dot bad";
}

function renderHealth(payload) {
  state.health = payload;
  const adbDevices = payload.adb.devices || [];
  const rows = [
    {
      ok: payload.adb.ok && adbDevices.length > 0,
      warn: payload.adb.ok && adbDevices.length === 0,
      text: payload.adb.ok ? `ADB: ${adbDevices.length || 0} device(s)` : "ADB: unavailable",
    },
    {
      ok: payload.ollama.ok && payload.ollama.modelReady,
      warn: payload.ollama.ok && !payload.ollama.modelReady,
      text: payload.ollama.ok ? `Ollama: ${payload.ollama.model}` : "Ollama: offline",
    },
    {
      ok: payload.ollama.ok && payload.ollama.embeddingReady,
      warn: payload.ollama.ok && !payload.ollama.embeddingReady,
      text: payload.ollama.ok ? `Embeddings: ${payload.ollama.embeddingModel}` : "Embeddings: offline",
    },
    {
      ok: payload.qdrant.ok,
      warn: false,
      text: payload.qdrant.ok ? "Qdrant: local" : "Qdrant: offline",
    },
  ];
  $("health").innerHTML = rows
    .map((row) => `<div class="status-row"><span class="${statusDot(row.ok, row.warn)}"></span><span>${row.text}</span></div>`)
    .join("");
}

async function refreshHealth() {
  const payload = await api("/api/health");
  renderHealth(payload);
}

async function loadProfiles() {
  const payload = await api("/api/profiles");
  state.presets = payload.presets || {};
  $("profilePreset").innerHTML = Object.keys(state.presets)
    .map((key) => `<option value="${key}">${key}</option>`)
    .join("");
  if (state.presets.default_ecommerce) {
    $("profilePreset").value = "default_ecommerce";
    applyProfile(state.presets.default_ecommerce);
  }
}

async function loadPackages() {
  const exportPath = encodeURIComponent($("exportPath").value);
  const payload = await api(`/api/packages?exportPath=${exportPath}`);
  const packages = payload.packages || [];
  $("targetPackage").innerHTML = packages
    .map((item) => {
      const label = item.appLabel || item.packageName;
      const decision = item.decision ? ` [${item.decision}]` : "";
      return `<option value="${item.packageName}">${label} - ${item.packageName}${decision}</option>`;
    })
    .join("");
  setLog(`Loaded ${packages.length} package(s).`);
}

async function pullExport() {
  setLog("Pulling latest AURA export from connected Android device...");
  const payload = await api("/api/pull-export", {
    method: "POST",
    body: JSON.stringify({}),
  });
  $("exportPath").value = payload.exportPath;
  setLog(`Pulled export to ${payload.exportPath}`);
  await loadPackages();
}

function renderCounts(audit) {
  const counts = audit.priorityCounts || {};
  const metrics = [
    ["P1", counts.P1 || 0],
    ["P2", counts.P2 || 0],
    ["P3", counts.P3 || 0],
    ["Areas", (audit.findingGroups || []).length],
  ];
  $("counts").innerHTML = metrics
    .map(([label, value]) => `<div class="metric"><strong>${value}</strong><span>${label}</span></div>`)
    .join("");
}

function readinessClass(status) {
  if (status === "PASS") return "good";
  if (status === "REVIEW_RECOMMENDED" || status === "NEEDS_FIXES") return "warn";
  if (status === "BLOCKED") return "bad";
  return "muted";
}

function chipClass(priority) {
  if (priority === "P1") return "chip red";
  if (priority === "P2" || priority === "P3") return "chip amber";
  return "chip green";
}

function renderGroups(audit) {
  const groups = audit.findingGroups || [];
  if (!groups.length) {
    $("groups").className = "group-list empty";
    $("groups").textContent = "No customer-visible review areas were generated.";
    return;
  }
  $("groups").className = "group-list";
  $("groups").innerHTML = groups
    .map((group) => {
      const statusClass = group.status === "BLOCKER" ? "blocker" : group.status === "REVIEW" ? "review" : "";
      const strength = group.evidenceStrength || {};
      const review = (group.recommendedReview || []).slice(0, 4).map((item) => `<li>${item}</li>`).join("");
      return `
        <article class="group-card ${statusClass}">
          <h4>${group.title}</h4>
          <div class="meta-line">
            <span class="${chipClass(group.priority)}">${group.priority}</span>
            <span class="chip">${group.status}</span>
            <span class="chip">${group.findingCount || 0} finding(s)</span>
            <span class="chip">${group.componentCount || 0} component(s)</span>
          </div>
          <p>${group.customerSummary || "No summary available."}</p>
          <p class="hint">Evidence: ${strength.level || "unknown"}; exploitability: ${strength.exploitability || "unknown"}.</p>
          ${review ? `<ul>${review}</ul>` : ""}
        </article>`;
    })
    .join("");
}

function llmClass(llm) {
  if (!llm) return "warn";
  const validation = llm.validation || {};
  if (validation.accepted && !validation.fallbackUsed) return "good";
  if (validation.accepted) return "warn";
  return "warn";
}

function llmLabel(llm) {
  if (!llm) return "Not run";
  if (llm.source === "rule_based_template_no_review_areas") return "No review areas to summarize";
  if (llm.source === "local_llm_validated") return "Local LLM validated";
  if (llm.source === "local_llm_partially_validated") return "Local LLM partial fallback";
  if (llm.source === "rule_based_template_after_llm_error") return "Template fallback after LLM error";
  if (llm.source === "rule_based_template_after_invalid_llm") return "Template fallback after invalid LLM";
  if (llm.source === "rule_based_template") return "Template summary";
  return llm.source || "Unknown";
}

function renderResult(payload) {
  state.lastResult = payload;
  const audit = payload.audit || {};
  const release = audit.releaseStatus || {};
  $("readiness").className = `readiness ${readinessClass(release.status)}`;
  $("readiness").textContent = release.status || "Unknown";
  renderCounts(audit);
  renderGroups(audit);
  $("llmStatus").className = `readiness ${llmClass(payload.llm)}`;
  $("llmStatus").textContent = llmLabel(payload.llm);
  $("llmDetail").textContent = payload.llm && payload.llm.validation
    ? JSON.stringify(payload.llm.validation)
    : "";
  $("openReport").href = payload.reportUrl;
  $("openReport").classList.remove("disabled");
  $("reportFrame").src = payload.reportUrl;
}

async function runAudit() {
  const targetPackage = $("targetPackage").value;
  if (!targetPackage) {
    setLog("Load packages and choose a target package first.");
    return;
  }
  const body = {
    exportPath: $("exportPath").value,
    offlineAnalysisPath: $("offlineAnalysisPath").value,
    targetPackage,
    profile: currentProfile(),
    privacyMode: $("privacyMode").value,
    basename: $("basename").value,
    llmEnabled: $("llmEnabled").checked,
  };
  $("runAudit").disabled = true;
  setLog("Running audit, LLM/RAG summary, and report generation...");
  try {
    const payload = await api("/api/run-audit", {
      method: "POST",
      body: JSON.stringify(body),
    });
    renderResult(payload);
    setLog(`Done.\nReport: ${payload.reportMarkdownPath}\nAudit: ${payload.auditPath}`);
  } catch (error) {
    setLog(`Failed: ${error.message}`);
  } finally {
    $("runAudit").disabled = false;
  }
}

function wireEvents() {
  $("refreshHealth").addEventListener("click", refreshHealth);
  $("loadPackages").addEventListener("click", loadPackages);
  $("pullExport").addEventListener("click", pullExport);
  $("runAudit").addEventListener("click", runAudit);
  $("profilePreset").addEventListener("change", () => {
    applyProfile(state.presets[$("profilePreset").value] || {});
  });
}

async function init() {
  wireEvents();
  await Promise.all([refreshHealth(), loadProfiles()]);
  await loadPackages().catch((error) => setLog(`Package load skipped: ${error.message}`));
}

init().catch((error) => setLog(error.message));
