/**
 * SENTINEL AI // REACTIVE SINGLE PAGE APPLICATION CONTROLLER
 * Zero-flicker tab routing, REST API communication, Chart.js telemetry, and forensic drawer.
 */

const AppState = {
  activeTab: 'overview',
  threshold: 0.50,
  overviewData: null,
  diagnosticsData: null,
  selectedAlertId: null,
  charts: {}
};

// Attack Preset Profiles
const PRESETS = {
  normal: { duration: 8.5, packets: 22, bytes: 2400, failed_connections: 0, unique_ports: 1 },
  portscan: { duration: 18.0, packets: 95, bytes: 4800, failed_connections: 2, unique_ports: 16 },
  exfil: { duration: 45.0, packets: 80, bytes: 48000, failed_connections: 0, unique_ports: 3 },
  bruteforce: { duration: 22.0, packets: 52, bytes: 3600, failed_connections: 9, unique_ports: 2 },
  ddos: { duration: 6.0, packets: 125, bytes: 22000, failed_connections: 4, unique_ports: 8 }
};

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initCanvas();
  initSandbox();
  initModelLab();
  initDataStudio();
  fetchOverviewData();
  fetchDiagnosticsData();

  // Polling for simulated packet counter update
  setInterval(() => {
    const el = document.getElementById('live-throughput');
    if (el) {
      const val = 1420 + Math.floor(Math.random() * 80 - 40);
      el.innerText = `${val.toLocaleString()} flows/s`;
    }
  }, 2500);
});

// -------------------------------------------------------------
// NAVIGATION & VIEW SWITCHING
// -------------------------------------------------------------
function initNavigation() {
  const navButtons = document.querySelectorAll('.nav-btn');
  navButtons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      const target = btn.dataset.target;
      switchTab(target);
    });
  });

  // Hotkeys: 1 to 5 for quick tab switching, Esc for closing drawer
  window.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    if (e.key === '1') switchTab('overview');
    if (e.key === '2') switchTab('threats');
    if (e.key === '3') switchTab('sandbox');
    if (e.key === '4') switchTab('models');
    if (e.key === '5') switchTab('data');
    if (e.key === 'Escape') closeDrawer();
  });
}

function switchTab(tabId) {
  AppState.activeTab = tabId;

  // Update nav buttons
  document.querySelectorAll('.nav-btn').forEach(btn => {
    if (btn.dataset.target === tabId) {
      btn.classList.add('active', 'border-cyan-500/50', 'text-cyan-400');
      btn.classList.remove('border-transparent', 'text-slate-400');
    } else {
      btn.classList.remove('active', 'border-cyan-500/50', 'text-cyan-400');
      btn.classList.add('border-transparent', 'text-slate-400');
    }
  });

  // Switch view containers
  document.querySelectorAll('.tab-view').forEach(view => {
    if (view.id === `view-${tabId}`) {
      view.classList.remove('hidden');
    } else {
      view.classList.add('hidden');
    }
  });

  if (tabId === 'threats') {
    loadAlertsTable();
  } else if (tabId === 'models') {
    renderModelCharts();
  }
}

// -------------------------------------------------------------
// NETWORK TOPOLOGY CANVAS
// -------------------------------------------------------------
let networkCanvasInstance = null;
function initCanvas() {
  networkCanvasInstance = new NetworkFlowCanvas('network-canvas');

  const btnInject = document.getElementById('btn-inject-threat');
  if (btnInject) {
    btnInject.addEventListener('click', () => {
      if (networkCanvasInstance) {
        networkCanvasInstance.injectThreat();
        showToast('Adversary Anomaly Injected into Stream', 'warning');
      }
    });
  }

  const btnSpeed = document.getElementById('btn-canvas-speed');
  if (btnSpeed) {
    btnSpeed.addEventListener('click', () => {
      if (!networkCanvasInstance) return;
      if (networkCanvasInstance.speed === 1.0) {
        networkCanvasInstance.speed = 2.0;
        btnSpeed.innerText = 'Speed: 2x';
      } else if (networkCanvasInstance.speed === 2.0) {
        networkCanvasInstance.speed = 3.5;
        btnSpeed.innerText = 'Speed: 3.5x';
      } else {
        networkCanvasInstance.speed = 1.0;
        btnSpeed.innerText = 'Speed: 1x';
      }
    });
  }
}

// -------------------------------------------------------------
// OVERVIEW & TELEMETRY API
// -------------------------------------------------------------
async function fetchOverviewData() {
  try {
    const res = await fetch(`/api/overview?threshold=${AppState.threshold}`);
    const data = await res.json();
    AppState.overviewData = data;

    // Update KPI metrics
    document.getElementById('kpi-total-flows').innerText = data.total_records.toLocaleString();
    document.getElementById('kpi-flagged-threats').innerText = data.flagged_threats.toLocaleString();
    document.getElementById('kpi-flag-rate').innerText = `${data.threat_rate_pct}% flag rate`;
    document.getElementById('kpi-f1-score').innerText = (data.f1_score * 100).toFixed(1) + '%';
    document.getElementById('kpi-accuracy').innerText = (data.accuracy * 100).toFixed(1) + '%';
    document.getElementById('header-model-name').innerText = data.active_model;

    // Populate Overview Recent Incidents Feed
    const feedBody = document.getElementById('overview-incident-feed');
    if (feedBody) {
      feedBody.innerHTML = '';
      data.recent_alerts.slice(0, 7).forEach(alert => {
        const tr = document.createElement('tr');
        tr.className = 'border-b border-slate-800/60 hover:bg-slate-800/30 cursor-pointer transition';
        tr.onclick = () => openDrawer(alert.id);

        const sevBadge = getSeverityBadgeHtml(alert.severity);
        tr.innerHTML = `
          <td class="py-3 px-4 font-mono text-xs font-semibold text-cyan-400">${alert.id}</td>
          <td class="py-3 px-4">${sevBadge}</td>
          <td class="py-3 px-4 font-mono text-sm font-bold ${alert.risk_score >= 80 ? 'text-rose-400' : 'text-amber-400'}">${alert.risk_score}/100</td>
          <td class="py-3 px-4 text-xs text-slate-300 font-medium">${alert.reason}</td>
          <td class="py-3 px-4 font-mono text-xs text-slate-400">${alert.packets} pkts · ${alert.bytes.toLocaleString()} B</td>
          <td class="py-3 px-4 text-right">
            <button class="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">Inspect</button>
          </td>
        `;
        feedBody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error('Error loading overview:', err);
  }
}

// -------------------------------------------------------------
// THREAT QUEUE & ALERTS
// -------------------------------------------------------------
async function loadAlertsTable() {
  const searchInput = document.getElementById('threat-search-input');
  const query = searchInput ? searchInput.value : '';
  const minRisk = document.getElementById('threat-min-risk') ? document.getElementById('threat-min-risk').value : 0;

  try {
    const res = await fetch(`/api/alerts?search=${encodeURIComponent(query)}&min_risk=${minRisk}&page_size=50`);
    const data = await res.json();

    const tbody = document.getElementById('threats-table-body');
    const countEl = document.getElementById('threats-count-badge');
    if (countEl) countEl.innerText = `${data.total} Incidents`;

    if (!tbody) return;
    tbody.innerHTML = '';

    if (data.items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="py-8 text-center text-slate-400 text-sm">No threat flows match the selected filter criteria.</td></tr>`;
      return;
    }

    data.items.forEach(alert => {
      const tr = document.createElement('tr');
      tr.className = 'border-b border-slate-800/70 hover:bg-slate-800/40 cursor-pointer transition';
      tr.onclick = (e) => {
        openDrawer(alert.id);
      };

      const sevBadge = getSeverityBadgeHtml(alert.severity);
      tr.innerHTML = `
        <td class="py-3.5 px-4 font-mono text-xs font-bold text-cyan-400">${alert.id}</td>
        <td class="py-3.5 px-4">${sevBadge}</td>
        <td class="py-3.5 px-4 font-mono text-sm font-bold text-slate-200">
          <span class="${alert.risk_score >= 80 ? 'text-rose-400' : 'text-amber-400'}">${alert.risk_score}</span><span class="text-xs text-slate-500">/100</span>
        </td>
        <td class="py-3.5 px-4 text-xs font-medium text-slate-300">${alert.reason}</td>
        <td class="py-3.5 px-4 font-mono text-xs text-slate-400">${alert.duration}s</td>
        <td class="py-3.5 px-4 font-mono text-xs text-slate-400">${alert.failed_connections} / ${alert.unique_ports}</td>
        <td class="py-3.5 px-4 text-right">
          <button class="px-3 py-1 text-xs rounded-lg bg-cyan-950/60 text-cyan-400 hover:bg-cyan-900 border border-cyan-800/60 font-medium">Inspect ➔</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Failed to load alerts table:', err);
  }
}

function getSeverityBadgeHtml(severity) {
  const s = (severity || 'Medium').toLowerCase();
  if (s === 'critical') return `<span class="px-2.5 py-0.5 rounded-full text-xs font-semibold badge-critical">CRITICAL</span>`;
  if (s === 'high') return `<span class="px-2.5 py-0.5 rounded-full text-xs font-semibold badge-high">HIGH</span>`;
  if (s === 'medium') return `<span class="px-2.5 py-0.5 rounded-full text-xs font-semibold badge-medium">MEDIUM</span>`;
  return `<span class="px-2.5 py-0.5 rounded-full text-xs font-semibold badge-low">LOW</span>`;
}

// -------------------------------------------------------------
// FORENSIC SLIDE-OVER DRAWER
// -------------------------------------------------------------
async function openDrawer(flowId) {
  AppState.selectedAlertId = flowId;
  const drawer = document.getElementById('forensic-drawer');
  const backdrop = document.getElementById('drawer-backdrop');

  if (!drawer) return;
  drawer.classList.remove('translate-x-full');
  if (backdrop) backdrop.classList.remove('hidden');

  document.getElementById('drawer-flow-id').innerText = flowId;
  document.getElementById('drawer-loading').classList.remove('hidden');
  document.getElementById('drawer-body').classList.add('hidden');

  try {
    const res = await fetch(`/api/alert/${flowId}`);
    const data = await res.json();

    document.getElementById('drawer-loading').classList.add('hidden');
    document.getElementById('drawer-body').classList.remove('hidden');

    // Severity & Risk Score
    const sevBadge = getSeverityBadgeHtml(data.severity);
    document.getElementById('drawer-sev-badge').innerHTML = sevBadge;
    document.getElementById('drawer-risk-score').innerText = `${data.composite_risk_score}/100`;
    document.getElementById('drawer-risk-bar').style.width = `${data.composite_risk_score}%`;
    document.getElementById('drawer-prob-score').innerText = `${data.threat_percentage}% Anomaly Likelihood`;

    // Recommended Action
    document.getElementById('drawer-action-text').innerText = data.recommended_action;

    // Heuristic Flags
    const flagsContainer = document.getElementById('drawer-flags-list');
    flagsContainer.innerHTML = '';
    data.flags.forEach(flag => {
      const box = document.createElement('div');
      box.className = 'p-3 rounded-lg border border-slate-700/60 bg-slate-800/40';
      box.innerHTML = `
        <div class="text-xs font-bold ${flag.type === 'danger' ? 'text-rose-400' : 'text-amber-400'} flex items-center gap-1.5">
          <span>●</span> ${flag.title}
        </div>
        <div class="text-xs text-slate-300 mt-1">${flag.desc}</div>
      `;
      flagsContainer.appendChild(box);
    });

    // Baseline Deviations
    const devContainer = document.getElementById('drawer-deviations-list');
    devContainer.innerHTML = '';
    for (const [key, dev] of Object.entries(data.deviations)) {
      const row = document.createElement('div');
      row.className = 'flex items-center justify-between py-1.5 border-b border-slate-800/60 text-xs';
      row.innerHTML = `
        <span class="text-slate-400 capitalize">${key.replace('_', ' ')}</span>
        <div class="flex items-center gap-2">
          <span class="font-mono font-bold text-slate-200">${dev.value}</span>
          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono ${dev.ratio > 2.0 ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-slate-800 text-slate-400'}">${dev.ratio}x baseline</span>
        </div>
      `;
      devContainer.appendChild(row);
    }
  } catch (err) {
    console.error('Failed to load alert details:', err);
  }
}

function closeDrawer() {
  const drawer = document.getElementById('forensic-drawer');
  const backdrop = document.getElementById('drawer-backdrop');
  if (drawer) drawer.classList.add('translate-x-full');
  if (backdrop) backdrop.classList.add('hidden');
}

// -------------------------------------------------------------
// LIVE ATTACK SIMULATOR & SANDBOX
// -------------------------------------------------------------
function initSandbox() {
  // Preset buttons
  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.dataset.preset;
      applyPreset(type);
    });
  });

  // Slider change listeners
  ['duration', 'packets', 'bytes', 'failed_connections', 'unique_ports'].forEach(param => {
    const slider = document.getElementById(`sim-${param}`);
    const display = document.getElementById(`val-${param}`);
    if (slider) {
      slider.addEventListener('input', () => {
        if (display) display.innerText = slider.value;
        triggerSimulation();
      });
    }
  });

  // Initial trigger
  triggerSimulation();
}

function applyPreset(presetKey) {
  const p = PRESETS[presetKey];
  if (!p) return;

  for (const [key, val] of Object.entries(p)) {
    const slider = document.getElementById(`sim-${key}`);
    const display = document.getElementById(`val-${key}`);
    if (slider) slider.value = val;
    if (display) display.innerText = val;
  }

  triggerSimulation();
  showToast(`Applied Preset: ${presetKey.toUpperCase()}`, 'info');
}

let simDebounceTimer = null;
function triggerSimulation() {
  clearTimeout(simDebounceTimer);
  simDebounceTimer = setTimeout(async () => {
    const payload = {
      duration: parseFloat(document.getElementById('sim-duration').value),
      packets: parseInt(document.getElementById('sim-packets').value),
      bytes: parseFloat(document.getElementById('sim-bytes').value),
      failed_connections: parseInt(document.getElementById('sim-failed_connections').value),
      unique_ports: parseInt(document.getElementById('sim-unique_ports').value),
      threshold: AppState.threshold
    };

    try {
      const res = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      updateSandboxDisplay(data);
    } catch (err) {
      console.error('Simulation error:', err);
    }
  }, 120);
}

function updateSandboxDisplay(data) {
  const gaugePercent = document.getElementById('sim-gauge-percent');
  const verdictBanner = document.getElementById('sim-verdict-banner');
  const verdictText = document.getElementById('sim-verdict-text');
  const verdictDesc = document.getElementById('sim-verdict-desc');
  const actionText = document.getElementById('sim-action-text');

  if (gaugePercent) gaugePercent.innerText = `${data.threat_percentage}%`;

  if (data.is_anomaly) {
    verdictBanner.className = 'p-4 rounded-xl border border-rose-500/40 bg-rose-950/20 text-rose-300';
    verdictText.innerText = `⚠️ SUSPICIOUS ANOMALY DETECTED [${data.severity.toUpperCase()}]`;
    verdictDesc.innerText = `Flow scored ${data.composite_risk_score}/100 on the composite risk index. Exceeded cutoff ${data.threshold_used}.`;
  } else {
    verdictBanner.className = 'p-4 rounded-xl border border-emerald-500/40 bg-emerald-950/20 text-emerald-300';
    verdictText.innerText = '✅ BENIGN / NORMAL NETWORK PATTERN';
    verdictDesc.innerText = 'Flow attributes align comfortably with baseline operational telemetry.';
  }

  if (actionText) actionText.innerText = data.recommended_action;

  // Render heuristic cards
  const flagsContainer = document.getElementById('sim-flags-container');
  if (flagsContainer) {
    flagsContainer.innerHTML = '';
    data.flags.forEach(flag => {
      const el = document.createElement('div');
      el.className = 'p-3 rounded-lg border border-slate-800 bg-slate-900/60 text-xs';
      el.innerHTML = `
        <div class="font-bold ${flag.type === 'danger' ? 'text-rose-400' : 'text-amber-400'}">${flag.title}</div>
        <div class="text-slate-300 mt-1">${flag.desc}</div>
      `;
      flagsContainer.appendChild(el);
    });
  }
}

// -------------------------------------------------------------
// AI MODEL LAB & DIAGNOSTICS CHARTS
// -------------------------------------------------------------
async function fetchDiagnosticsData() {
  try {
    const res = await fetch(`/api/diagnostics?threshold=${AppState.threshold}`);
    const data = await res.json();
    AppState.diagnosticsData = data;
    renderModelCharts();
  } catch (err) {
    console.error('Failed to load diagnostics:', err);
  }
}

function initModelLab() {
  const modelSelect = document.getElementById('model-select-algo');
  const btnRetrain = document.getElementById('btn-retrain-model');
  const threshSlider = document.getElementById('model-threshold-slider');

  if (threshSlider) {
    threshSlider.addEventListener('input', () => {
      const val = parseFloat(threshSlider.value);
      AppState.threshold = val;
      document.getElementById('model-threshold-val').innerText = val.toFixed(2);
      fetchOverviewData();
      fetchDiagnosticsData();
    });
  }

  if (btnRetrain) {
    btnRetrain.addEventListener('click', async () => {
      btnRetrain.disabled = true;
      btnRetrain.innerText = 'Training...';
      const algo = modelSelect ? modelSelect.value : 'Random Forest';
      const estimators = parseInt(document.getElementById('model-n-estimators').value || 150);

      try {
        const res = await fetch('/api/model/train', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model_type: algo,
            n_estimators: estimators,
            threshold: AppState.threshold
          })
        });
        const data = await res.json();
        showToast(data.message, 'success');
        fetchOverviewData();
        fetchDiagnosticsData();
      } catch (err) {
        showToast('Training failed', 'danger');
      } finally {
        btnRetrain.disabled = false;
        btnRetrain.innerText = 'Retrain Ensemble';
      }
    });
  }
}

function initDataStudio() {
  const genRatio = document.getElementById('gen-ratio');
  const genRatioVal = document.getElementById('gen-ratio-val');
  const btnGen = document.getElementById('btn-generate-data');

  if (genRatio && genRatioVal) {
    genRatio.addEventListener('input', () => {
      const pct = Math.round(parseFloat(genRatio.value) * 100);
      genRatioVal.innerText = `${pct}% Suspicious`;
    });
  }

  if (btnGen) {
    btnGen.addEventListener('click', async () => {
      btnGen.disabled = true;
      btnGen.innerText = '⚡ Synthesizing Telemetry...';
      const count = parseInt(document.getElementById('gen-count')?.value || 2000);
      const ratio = parseFloat(genRatio ? genRatio.value : 0.5);

      try {
        const res = await fetch('/api/generate-data', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            n_samples: count,
            anomaly_ratio: ratio,
            seed: 42
          })
        });
        const data = await res.json();
        showToast(`Synthesized ${data.total_records} flows with ${(data.anomaly_ratio * 100).toFixed(0)}% anomalies.`, 'success');
        fetchOverviewData();
        fetchDiagnosticsData();
        loadAlertsTable();
      } catch (err) {
        showToast('Data generation failed: ' + err.message, 'danger');
      } finally {
        btnGen.disabled = false;
        btnGen.innerText = '⚡ Synthesize & Overwrite Telemetry';
      }
    });
  }
}

function renderModelCharts() {
  const data = AppState.diagnosticsData;
  if (!data) return;

  // 1. Confusion Matrix
  const cm = data.confusion_matrix;
  document.getElementById('cm-tn').innerText = cm.tn;
  document.getElementById('cm-fp').innerText = cm.fp;
  document.getElementById('cm-fn').innerText = cm.fn;
  document.getElementById('cm-tp').innerText = cm.tp;

  // Metrics summary
  document.getElementById('diag-auc-roc').innerText = data.roc_auc.toFixed(3);
  document.getElementById('diag-auc-pr').innerText = data.pr_auc.toFixed(3);
  document.getElementById('diag-f1').innerText = (data.f1_score * 100).toFixed(1) + '%';
  document.getElementById('diag-precision').innerText = (data.precision * 100).toFixed(1) + '%';

  // 2. ROC Curve Chart.js
  const rocCanvas = document.getElementById('chart-roc-curve');
  if (rocCanvas && window.Chart) {
    if (AppState.charts.roc) AppState.charts.roc.destroy();

    const rocPoints = data.roc_curve.map(pt => ({ x: pt.fpr, y: pt.tpr }));
    AppState.charts.roc = new Chart(rocCanvas, {
      type: 'line',
      data: {
        datasets: [
          {
            label: `ROC Curve (AUC = ${data.roc_auc})`,
            data: rocPoints,
            borderColor: '#06b6d4',
            backgroundColor: 'rgba(6, 182, 212, 0.15)',
            fill: true,
            tension: 0.2,
            borderWidth: 2.5
          },
          {
            label: 'Chance Line',
            data: [{ x: 0, y: 0 }, { x: 1, y: 1 }],
            borderColor: '#64748b',
            borderDash: [5, 5],
            borderWidth: 1.5,
            pointRadius: 0
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { type: 'linear', min: 0, max: 1, grid: { color: 'rgba(255,255,255,0.06)' }, title: { display: true, text: 'False Positive Rate', color: '#94a3b8' } },
          y: { type: 'linear', min: 0, max: 1, grid: { color: 'rgba(255,255,255,0.06)' }, title: { display: true, text: 'True Positive Rate', color: '#94a3b8' } }
        },
        plugins: {
          legend: { labels: { color: '#cbd5e1' } }
        }
      }
    });
  }

  // 3. Feature Importance Bar Chart
  const fiCanvas = document.getElementById('chart-feature-importance');
  if (fiCanvas && window.Chart) {
    if (AppState.charts.fi) AppState.charts.fi.destroy();

    const labels = data.feature_importance.map(f => f.feature.replace('_', ' '));
    const values = data.feature_importance.map(f => f.importance);

    AppState.charts.fi = new Chart(fiCanvas, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Gini Importance',
          data: values,
          backgroundColor: '#3b82f6',
          borderRadius: 6
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#94a3b8' } },
          y: { grid: { display: false }, ticks: { color: '#cbd5e1' } }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }
}

// -------------------------------------------------------------
// TOAST NOTIFICATIONS & ACTIONS
// -------------------------------------------------------------
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  const bg = type === 'danger' ? 'border-rose-500 bg-rose-950 text-rose-200'
    : type === 'warning' ? 'border-amber-500 bg-amber-950 text-amber-200'
    : type === 'success' ? 'border-emerald-500 bg-emerald-950 text-emerald-200'
    : 'border-cyan-500 bg-slate-900 text-cyan-200';

  toast.className = `p-3.5 rounded-xl border shadow-2xl flex items-center gap-3 text-xs font-medium transition-all duration-300 transform translate-y-4 opacity-0 ${bg}`;
  toast.innerHTML = `<span>🛡️</span><span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.remove('translate-y-4', 'opacity-0');
  }, 10);

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-y-2');
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function handleQuarantineCurrent() {
  const id = AppState.selectedAlertId || 'Current Host';
  showToast(`Quarantine command broadcast: ${id} isolated at SDN controller.`, 'danger');
  closeDrawer();
}

function handleExportCurrent() {
  const id = AppState.selectedAlertId || 'flow';
  showToast(`Forensic PCAP metadata for ${id} exported to clipboard.`, 'success');
}
