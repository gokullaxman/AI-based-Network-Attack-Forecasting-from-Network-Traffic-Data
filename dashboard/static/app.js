/**
 * AI-Based Network Attack Forecasting System - Dashboard Controller
 * Implements data fetching, count-up animations (600-800ms), 
 * card fade/slide transitions (200-300ms), stage progression glow highlights,
 * risk badge cross-fade, and in-place SHAP tab switching.
 */

// State tracking
let currentState = {
  currentStage: null,
  predictedNextStage: null,
  confidence: 0,
  riskScore: 0,
  riskLevel: null,
  isFirstLoad: true
};

// DOM Elements
const bannerCurrent = document.getElementById("bannerCurrent");
const bannerNext = document.getElementById("bannerNext");
const bannerConfidence = document.getElementById("bannerConfidence");
const bannerRiskBadge = document.getElementById("bannerRiskBadge");

const confidenceValue = document.getElementById("confidenceValue");
const riskScoreValue = document.getElementById("riskScoreValue");
const riskLevelBadge = document.getElementById("riskLevelBadge");

const currentStageCard = document.getElementById("currentStageCard");
const currentStageTitle = document.getElementById("currentStageTitle");
const currentStageDesc = document.getElementById("currentStageDesc");

const predictedStageCard = document.getElementById("predictedStageCard");
const predictedStageTitle = document.getElementById("predictedStageTitle");
const predictedStageDesc = document.getElementById("predictedStageDesc");

const responseCard = document.getElementById("responseCard");
const defenseOptionsList = document.getElementById("defenseOptionsList");

const stepNodes = document.querySelectorAll(".step-node");
const streamTriggerBtn = document.getElementById("streamTriggerBtn");
const loadRealBtn = document.getElementById("loadRealBtn");
const exportExcelBtn = document.getElementById("exportExcelBtn");
const liveLabel = document.getElementById("liveLabel");

// Client-side session forecast history for export
const sessionForecasts = [];

// SHAP Tab Elements
const tabRankingBtn = document.getElementById("tabRankingBtn");
const tabForceBtn = document.getElementById("tabForceBtn");
const panelRanking = document.getElementById("panelRanking");
const panelForce = document.getElementById("panelForce");
const shapRankingBody = document.getElementById("shapRankingBody");
const forceBarsList = document.getElementById("forceBarsList");
const forceBaseVal = document.getElementById("forceBaseVal");
const forceOutputVal = document.getElementById("forceOutputVal");


/**
 * Smooth Count-Up Animation (600 - 800ms duration)
 */
function animateCountUp(element, startVal, targetVal, durationMs = 700, suffix = "") {
  const startTime = performance.now();
  
  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(1.0, elapsed / durationMs);
    // Ease-out cubic calculation
    const easeOut = 1 - Math.pow(1 - progress, 3);
    const currentVal = Math.round(startVal + (targetVal - startVal) * easeOut);
    
    element.textContent = currentVal + suffix;
    
    if (progress < 1.0) {
      requestAnimationFrame(update);
    } else {
      element.textContent = targetVal + suffix;
    }
  }
  
  requestAnimationFrame(update);
}


/**
 * Cross-fade Risk Badge with smooth color/label transition
 */
function updateRiskBadge(badgeEl, newLevel) {
  if (currentState.riskLevel === newLevel && !currentState.isFirstLoad) {
    return;
  }
  
  // Fade out slightly
  badgeEl.style.opacity = "0.2";
  
  setTimeout(() => {
    badgeEl.textContent = newLevel;
    
    // Set subtle accent color theme
    if (newLevel === "HIGH") {
      badgeEl.style.color = "var(--risk-high-accent)";
      badgeEl.style.backgroundColor = "var(--risk-high-bg)";
      badgeEl.style.borderColor = "var(--risk-high-accent)";
    } else if (newLevel === "MEDIUM") {
      badgeEl.style.color = "var(--risk-med-accent)";
      badgeEl.style.backgroundColor = "var(--risk-med-bg)";
      badgeEl.style.borderColor = "var(--risk-med-accent)";
    } else {
      badgeEl.style.color = "var(--risk-low-accent)";
      badgeEl.style.backgroundColor = "var(--risk-low-bg)";
      badgeEl.style.borderColor = "var(--risk-low-accent)";
    }
    
    // Fade in
    badgeEl.style.opacity = "1";
  }, 150);
}


const STAGE_ORDER = [
  "reconnaissance",
  "scanning",
  "enumeration",
  "exploitation",
  "intrusion"
];

/**
 * Update the horizontal attack-stage step indicator
 * Dynamically binds the highlight bar, connectors, and nodes to real model forecasts
 */
function updateStepIndicator(currentStage, predictedNextStage) {
  if (!currentStage) return;

  const currNorm = String(currentStage).trim().toLowerCase();
  const nextNorm = predictedNextStage ? String(predictedNextStage).trim().toLowerCase() : "";

  const currIdx = STAGE_ORDER.indexOf(currNorm);
  const nextIdx = STAGE_ORDER.indexOf(nextNorm);

  const nodes = document.querySelectorAll(".step-node");
  const connectors = document.querySelectorAll(".step-connector");

  nodes.forEach((node, idx) => {
    const stageAttr = (node.getAttribute("data-stage") || "").trim().toLowerCase();
    const tagEl = node.querySelector(".node-status-tag");

    node.classList.remove("is-current", "is-forecasted", "is-both", "is-passed");

    if (stageAttr === currNorm && stageAttr === nextNorm) {
      node.classList.add("is-both");
      if (tagEl) tagEl.textContent = "CURRENT ACTIVE & PERSISTING";
    } else if (stageAttr === currNorm) {
      node.classList.add("is-current");
      if (tagEl) tagEl.textContent = "CURRENT ACTIVE";
    } else if (stageAttr === nextNorm) {
      node.classList.add("is-forecasted");
      if (tagEl) tagEl.textContent = "FORECASTED NEXT";
    } else if (currIdx !== -1 && idx < currIdx) {
      node.classList.add("is-passed");
      if (tagEl) tagEl.textContent = "PASSED";
    } else {
      if (tagEl) tagEl.textContent = "STANDBY";
    }
  });

  // Dynamically update the connector highlight bar
  connectors.forEach((conn, idx) => {
    conn.classList.remove("is-active", "is-forecast-link");
    if (currIdx !== -1 && idx < currIdx) {
      // Connectors prior to current active stage
      conn.classList.add("is-active");
    } else if (
      (currIdx !== -1 && nextIdx !== -1 && idx === currIdx && nextIdx === currIdx + 1) ||
      (idx === Math.min(currIdx, nextIdx) && Math.abs(currIdx - nextIdx) === 1)
    ) {
      // Connector connecting current stage to forecasted next stage
      conn.classList.add("is-forecast-link");
    }
  });
}


/**
 * Populate SHAP Feature Attribution Ranking View
 */
function renderSHAPRanking(rankingData) {
  shapRankingBody.innerHTML = "";
  
  // Find max absolute attribution for relative bar width
  const maxAttr = Math.max(...rankingData.map((d) => d.abs_attribution), 0.001);
  
  rankingData.forEach((item) => {
    const tr = document.createElement("tr");
    const widthPct = Math.min(100, Math.round((item.abs_attribution / maxAttr) * 100));
    const isPositive = item.attribution >= 0;
    
    tr.innerHTML = `
      <td><span class="feat-name">${item.feature}</span></td>
      <td><span class="feat-desc">${item.description}</span></td>
      <td><span class="feat-val">${item.value}</span></td>
      <td>
        <span class="impact-badge ${isPositive ? 'positive' : 'negative'}">
          ${isPositive ? '+ Risk Driver' : '– Mitigating'}
        </span>
      </td>
      <td class="bar-cell">
        <div class="attr-bar-wrapper">
          <div class="attr-bar-bg">
            <div class="attr-bar-fill" style="width: ${widthPct}%; background-color: ${isPositive ? 'var(--accent-primary)' : '#10b981'};"></div>
          </div>
          <span class="attr-num">${item.attribution > 0 ? '+' : ''}${item.attribution.toFixed(4)}</span>
        </div>
      </td>
    `;
    shapRankingBody.appendChild(tr);
  });
}


/**
 * Populate SHAP Force-Plot-Style View
 */
function renderSHAPForcePlot(forceData) {
  forceBaseVal.textContent = forceData.base_value.toFixed(4);
  forceOutputVal.textContent = forceData.forecast_probability.toFixed(4);
  
  forceBarsList.innerHTML = "";
  
  const maxContrib = Math.max(...forceData.contributions.map((c) => Math.abs(c.contribution)), 0.001);
  
  forceData.contributions.forEach((c) => {
    const row = document.createElement("div");
    row.className = "force-bar-row";
    
    const widthPct = Math.min(100, Math.round((Math.abs(c.contribution) / maxContrib) * 100));
    const isPositive = c.contribution >= 0;
    
    row.innerHTML = `
      <span class="force-feat-name" title="${c.feature} (val: ${c.value})">${c.feature}</span>
      <div class="force-track">
        <div class="force-fill ${isPositive ? 'positive' : 'negative'}" style="width: ${widthPct}%;"></div>
      </div>
      <span class="force-val-label" style="color: ${isPositive ? '#ef4444' : '#10b981'};">
        ${isPositive ? '+' : ''}${c.contribution.toFixed(4)}
      </span>
    `;
    forceBarsList.appendChild(row);
  });
}


/**
 * Applies new forecast data with animations matching UI/UX rules
 */
function applyForecastData(data) {
  const isInitial = currentState.isFirstLoad;
  
  // 1. Exact Output Banner Update
  bannerCurrent.textContent = data.current_stage;
  bannerNext.textContent = data.predicted_next_stage;
  bannerConfidence.textContent = data.confidence + "%";
  bannerRiskBadge.textContent = data.risk_level;
  
  // Update banner risk badge tint
  if (data.risk_level === "HIGH") {
    bannerRiskBadge.style.backgroundColor = "var(--risk-high-accent)";
  } else if (data.risk_level === "MEDIUM") {
    bannerRiskBadge.style.backgroundColor = "var(--risk-med-accent)";
  } else {
    bannerRiskBadge.style.backgroundColor = "var(--risk-low-accent)";
  }

  // 2. Stat Callouts: Count-up animation (600-800ms)
  const prevConf = isInitial ? 0 : currentState.confidence;
  const prevRisk = isInitial ? 0 : currentState.riskScore;
  
  animateCountUp(confidenceValue, prevConf, data.confidence, 700);
  animateCountUp(riskScoreValue, prevRisk, data.risk_score, 700);
  
  // Risk badge cross-fade
  updateRiskBadge(riskLevelBadge, data.risk_level);

  // 3. Card Fade/Slide In Transitions (200-300ms ease-out)
  const animatedCards = [currentStageCard, predictedStageCard, responseCard];
  
  animatedCards.forEach((card) => card.classList.add("updating"));
  
  setTimeout(() => {
    currentStageTitle.textContent = data.current_stage;
    predictedStageTitle.textContent = data.predicted_next_stage;
    
    // Render Ranked Multiple Defense Options (2-4 items)
    if (data.recommendation && defenseOptionsList) {
      defenseOptionsList.innerHTML = "";
      const options = data.recommendation.options || [];
      
      if (options.length > 0) {
        options.forEach((opt) => {
          const itemDiv = document.createElement("div");
          itemDiv.className = "defense-option-item";
          itemDiv.innerHTML = `
            <div class="defense-priority-badge">${opt.priority}</div>
            <div class="defense-content">
              <div class="defense-action-title">${opt.action}</div>
              <div class="defense-rationale">${opt.rationale}</div>
            </div>
          `;
          defenseOptionsList.appendChild(itemDiv);
        });
      } else if (data.recommendation.title) {
        // Fallback for simple structure
        const itemDiv = document.createElement("div");
        itemDiv.className = "defense-option-item";
        itemDiv.innerHTML = `
          <div class="defense-priority-badge">1</div>
          <div class="defense-content">
            <div class="defense-action-title">${data.recommendation.title}</div>
            <div class="defense-rationale">${data.recommendation.description}</div>
          </div>
        `;
        defenseOptionsList.appendChild(itemDiv);
      }
    }
    
    // Smooth ease-out slide/fade back
    animatedCards.forEach((card) => card.classList.remove("updating"));
  }, 220);

  // 4. Horizontal Step Indicator Glow Update
  updateStepIndicator(data.current_stage, data.predicted_next_stage);

  // 5. SHAP attribution data updates
  if (data.shap) {
    if (data.shap.feature_ranking) {
      renderSHAPRanking(data.shap.feature_ranking);
    }
    if (data.shap.force_plot) {
      renderSHAPForcePlot(data.shap.force_plot);
    }
  }

  // Update tracking state
  currentState = {
    currentStage: data.current_stage,
    predictedNextStage: data.predicted_next_stage,
    confidence: data.confidence,
    riskScore: data.risk_score,
    riskLevel: data.risk_level,
    isFirstLoad: false
  };

  // Record into session history for export
  sessionForecasts.push(data);
  if (sessionForecasts.length > 300) {
    sessionForecasts.shift();
  }
}


/**
 * Fetch forecast from server (Initial or on-demand)
 */
async function fetchForecast() {
  try {
    const res = await fetch("/api/forecast", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    if (!res.ok) throw new Error("Forecast API error: " + res.statusText);
    const data = await res.json();
    applyForecastData(data);
  } catch (err) {
    console.error("Failed to fetch initial forecast:", err);
  }
}


/**
 * Fetch next flow window from /api/stream to advance attack timeline
 */
async function advanceStream() {
  try {
    streamTriggerBtn.disabled = true;
    streamTriggerBtn.style.opacity = "0.7";
    
    const res = await fetch("/api/stream");
    if (!res.ok) throw new Error("Stream API error: " + res.statusText);
    const data = await res.json();
    applyForecastData(data);
    if (liveLabel) {
      liveLabel.textContent = "LIVE FLOW STREAM";
    }
  } catch (err) {
    console.error("Failed to advance stream:", err);
  } finally {
    setTimeout(() => {
      streamTriggerBtn.disabled = false;
      streamTriggerBtn.style.opacity = "1";
    }, 400);
  }
}


// Real playback timer reference
let realPlaybackTimer = null;

/**
 * Load Real CICIDS2017/2018 CSV data via /api/ingest-real
 * Walks through sequential T=10 sliding windows and plays them back with animations
 */
async function loadRealCICIDS() {
  try {
    if (realPlaybackTimer) {
      clearInterval(realPlaybackTimer);
      realPlaybackTimer = null;
    }

    loadRealBtn.disabled = true;
    loadRealBtn.style.opacity = "0.7";
    
    const res = await fetch("/api/ingest-real");
    if (!res.ok) throw new Error("Real data ingestion error: " + res.statusText);
    const data = await res.json();
    
    const windows = data.windows || [data];
    let currentIdx = 0;
    
    // Apply first window immediately
    applyForecastData(windows[0]);
    if (liveLabel) {
      liveLabel.textContent = `CICIDS REAL (1/${windows.length})`;
    }
    
    if (windows.length > 1) {
      currentIdx = 1;
      realPlaybackTimer = setInterval(() => {
        if (currentIdx >= windows.length) {
          clearInterval(realPlaybackTimer);
          realPlaybackTimer = null;
          if (liveLabel) {
            liveLabel.textContent = "CICIDS REAL STREAM (COMPLETE)";
          }
          loadRealBtn.disabled = false;
          loadRealBtn.style.opacity = "1";
          return;
        }
        
        applyForecastData(windows[currentIdx]);
        if (liveLabel) {
          liveLabel.textContent = `CICIDS REAL (${currentIdx + 1}/${windows.length})`;
        }
        currentIdx++;
      }, 1400);
    } else {
      loadRealBtn.disabled = false;
      loadRealBtn.style.opacity = "1";
    }
    
  } catch (err) {
    console.error("Failed to ingest real CICIDS data:", err);
    loadRealBtn.disabled = false;
    loadRealBtn.style.opacity = "1";
  }
}


/**
 * Export current forecast session history to Excel (.xlsx)
 */
async function exportToExcel() {
  try {
    exportExcelBtn.disabled = true;
    exportExcelBtn.style.opacity = "0.7";
    const originalContent = exportExcelBtn.innerHTML;
    exportExcelBtn.innerHTML = `
      <svg class="btn-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
      Exporting...
    `;

    const res = await fetch("/api/export-xlsx", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ history: sessionForecasts })
    });

    if (!res.ok) throw new Error("Excel export request failed: " + res.statusText);

    const blob = await res.blob();
    
    // Determine filename
    let filename = "attack_forecast_export.xlsx";
    const disposition = res.headers.get("Content-Disposition");
    if (disposition && disposition.includes("filename=")) {
      const match = disposition.match(/filename="?([^";]+)"?/);
      if (match && match[1]) {
        filename = match[1];
      }
    } else {
      const ts = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
      filename = `attack_forecast_export_${ts}.xlsx`;
    }

    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);

  } catch (err) {
    console.error("Failed to export Excel file:", err);
  } finally {
    setTimeout(() => {
      exportExcelBtn.disabled = false;
      exportExcelBtn.style.opacity = "1";
      exportExcelBtn.innerHTML = `
        <svg class="btn-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
        Export to Excel
      `;
    }, 400);
  }
}


/**
 * Tab Switching with In-Place Cross-Fade
 */
function setupTabs() {
  tabRankingBtn.addEventListener("click", () => {
    if (tabRankingBtn.classList.contains("active")) return;
    
    tabRankingBtn.classList.add("active");
    tabRankingBtn.setAttribute("aria-selected", "true");
    tabForceBtn.classList.remove("active");
    tabForceBtn.setAttribute("aria-selected", "false");
    
    // Cross fade
    panelForce.style.opacity = "0";
    setTimeout(() => {
      panelForce.classList.remove("active");
      panelRanking.classList.add("active");
      panelRanking.style.opacity = "0";
      setTimeout(() => {
        panelRanking.style.opacity = "1";
      }, 30);
    }, 150);
  });

  tabForceBtn.addEventListener("click", () => {
    if (tabForceBtn.classList.contains("active")) return;
    
    tabForceBtn.classList.add("active");
    tabForceBtn.setAttribute("aria-selected", "true");
    tabRankingBtn.classList.remove("active");
    tabRankingBtn.setAttribute("aria-selected", "false");
    
    // Cross fade
    panelRanking.style.opacity = "0";
    setTimeout(() => {
      panelRanking.classList.remove("active");
      panelForce.classList.add("active");
      panelForce.style.opacity = "0";
      setTimeout(() => {
        panelForce.style.opacity = "1";
      }, 30);
    }, 150);
  });
}


// Wire buttons & live streaming loop
streamTriggerBtn.addEventListener("click", advanceStream);
loadRealBtn.addEventListener("click", loadRealCICIDS);
exportExcelBtn.addEventListener("click", exportToExcel);

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  fetchForecast();
  
  // Optional automated live flow progression every 7 seconds
  setInterval(() => {
    advanceStream();
  }, 7000);
});
