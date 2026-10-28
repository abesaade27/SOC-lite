/**
 * SOC-Lite Dashboard Application
 * Vanilla JS + Chart.js (No build-step)
 */

// Event ID friendly names catalog
const eventNames = {
  4624: "Logon success",
  4625: "Logon failure",
  4634: "Logoff",
  4647: "User initiated logoff",
  4648: "Explicit credentials",
  4672: "Special privileges assigned",
  4688: "Process created",
  4697: "Service installed",
  7045: "Service installed",
  4698: "Scheduled task created",
  4720: "User created",
  4722: "User enabled",
  4724: "Password reset",
  4725: "User disabled",
  4726: "User deleted",
  4728: "Added to global group",
  4732: "Added to local group",
  4756: "Added to universal group",
  4740: "Account lockout",
  1102: "Security log cleared",
  104: "System log cleared",
  4104: "PowerShell script block",
  1: "Sysmon Process create",
  3: "Sysmon Network connection",
  10: "Sysmon Process access",
  11: "Sysmon File create",
  13: "Sysmon Registry set",
  5001: "Defender protection disabled",
  5010: "Defender protection disabled",
  5012: "Defender protection disabled",
  1116: "Defender malware detected",
  1117: "Defender malware action",
};

// Application State
const state = {
  events: [],           // Buffer of latest 200 events
  alerts: [],           // Buffer of alerts
  isFeedPaused: false,
  audioEnabled: false,
  selectedRangeMinutes: 60,
  selectedHost: "",
  categoryFilter: "",
  searchQuery: "",
  alertSeverityFilter: "",
  alertStatusFilter: "new",
  charts: {},
  ws: null,
  wsReconnectDelay: 1000,
  activeAlert: null,
  activeEvent: null,
};

// Security helper: escape HTML to prevent XSS
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Audio Alert using Web Audio API
function playAlertBeep() {
  if (!state.audioEnabled) return;
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(880, audioCtx.currentTime); // A5 note
    gain.gain.setValueAtTime(0.15, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.3);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + 0.3);
  } catch (e) {
    console.debug("Audio error:", e);
  }
}

// Format timestamp helper
function formatTime(isoString) {
  if (!isoString) return "-";
  try {
    const d = new Date(isoString);
    return d.toISOString().replace("T", " ").replace("Z", "");
  } catch (e) {
    return isoString;
  }
}

// Initialize Charts
function initCharts() {
  if (!window.Chart) {
    console.warn("Chart.js is not loaded yet.");
    return;
  }

  const commonOptions = {
    responsive: true,
    maintainAspectRatio: false,
    color: "#8b949e",
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: "#18202c",
        borderColor: "#243042",
        borderWidth: 1,
        titleColor: "#e6edf3",
        bodyColor: "#8b949e",
      },
    },
    scales: {
      x: {
        grid: { color: "rgba(36, 48, 66, 0.4)" },
        ticks: { color: "#8b949e", font: { size: 10 } },
      },
      y: {
        grid: { color: "rgba(36, 48, 66, 0.4)" },
        ticks: { color: "#8b949e", font: { size: 10 }, precision: 0 },
      },
    },
  };

  // 1. Timeline Chart (Events per min)
  const ctxTimeline = document.getElementById("timelineChart").getContext("2d");
  state.charts.timeline = new Chart(ctxTimeline, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "Events",
          data: [],
          borderColor: "#00e5ff",
          backgroundColor: "rgba(0, 229, 255, 0.1)",
          fill: true,
          tension: 0.25,
          pointRadius: 2,
        },
      ],
    },
    options: commonOptions,
  });

  // 2. Top Event IDs (Horizontal Bar)
  const ctxEventIds = document.getElementById("eventIdsChart").getContext("2d");
  state.charts.eventIds = new Chart(ctxEventIds, {
    type: "bar",
    data: {
      labels: [],
      datasets: [
        {
          label: "Count",
          data: [],
          backgroundColor: "#388bfd",
          borderRadius: 3,
        },
      ],
    },
    options: {
      ...commonOptions,
      indexAxis: "y",
    },
  });

  // 3. Failed Logons by IP (Horizontal Bar)
  const ctxFailed = document.getElementById("failedLogonsChart").getContext("2d");
  state.charts.failedLogons = new Chart(ctxFailed, {
    type: "bar",
    data: {
      labels: [],
      datasets: [
        {
          label: "Failures",
          data: [],
          backgroundColor: "#ff7b00",
          borderRadius: 3,
        },
      ],
    },
    options: {
      ...commonOptions,
      indexAxis: "y",
    },
  });

  // 4. Alerts by Severity (Doughnut)
  const ctxSev = document.getElementById("severityChart").getContext("2d");
  state.charts.severity = new Chart(ctxSev, {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [
        {
          data: [0, 0, 0, 0],
          backgroundColor: ["#ff3366", "#ff7b00", "#e3b341", "#3fb950"],
          borderColor: "#121820",
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: true,
          position: "right",
          labels: { color: "#8b949e", font: { size: 11 } },
        },
      },
    },
  });
}

// Fetch & Update Stats Overview and Charts
async function refreshStats() {
  try {
    const res = await fetch(`/api/stats/overview?minutes=${state.selectedRangeMinutes}`);
    if (!res.ok) return;
    const stats = await res.json();

    // Update KPI cards
    document.getElementById("kpiTotalEvents").textContent = stats.total_events.toLocaleString();
    document.getElementById("kpiRate").textContent = stats.ingest_rate_1m.toFixed(1);
    document.getElementById("rateValue").textContent = `${stats.ingest_rate_1m.toFixed(1)} /s`;

    const openCount = (stats.alerts_by_severity.critical || 0) +
                      (stats.alerts_by_severity.high || 0) +
                      (stats.alerts_by_severity.medium || 0) +
                      (stats.alerts_by_severity.low || 0);
    document.getElementById("kpiOpenAlerts").textContent = openCount;
    document.getElementById("kpiCriticalAlerts").textContent = stats.alerts_by_severity.critical || 0;

    const failedLogonSum = stats.failed_logons_by_ip.reduce((acc, cur) => acc + cur.count, 0);
    document.getElementById("kpiFailedLogons").textContent = failedLogonSum.toLocaleString();

    // Populate Host filter if changed
    const hostSelect = document.getElementById("hostSelect");
    const currentVal = hostSelect.value;
    const existingOptions = new Set(Array.from(hostSelect.options).map((o) => o.value));
    stats.top_hosts.forEach((h) => {
      if (!existingOptions.has(h.name)) {
        const opt = document.createElement("option");
        opt.value = h.name;
        opt.textContent = `${h.name} (${h.count})`;
        hostSelect.appendChild(opt);
      }
    });
    hostSelect.value = currentVal;

    // Update Charts
    if (state.charts.timeline) {
      state.charts.timeline.data.labels = stats.events_per_minute.map((p) => p.t.substring(11, 16));
      state.charts.timeline.data.datasets[0].data = stats.events_per_minute.map((p) => p.count);
      state.charts.timeline.update("none");
    }

    if (state.charts.eventIds) {
      state.charts.eventIds.data.labels = stats.top_event_ids.map((item) => {
        const friendly = eventNames[parseInt(item.name, 10)] || "Other";
        return `${item.name} (${friendly})`;
      });
      state.charts.eventIds.data.datasets[0].data = stats.top_event_ids.map((item) => item.count);
      state.charts.eventIds.update("none");
    }

    if (state.charts.failedLogons) {
      state.charts.failedLogons.data.labels = stats.failed_logons_by_ip.map((item) => item.name);
      state.charts.failedLogons.data.datasets[0].data = stats.failed_logons_by_ip.map((item) => item.count);
      state.charts.failedLogons.update("none");
    }

    if (state.charts.severity) {
      state.charts.severity.data.datasets[0].data = [
        stats.alerts_by_severity.critical || 0,
        stats.alerts_by_severity.high || 0,
        stats.alerts_by_severity.medium || 0,
        stats.alerts_by_severity.low || 0,
      ];
      state.charts.severity.update("none");
    }
  } catch (err) {
    console.debug("Failed to refresh stats:", err);
  }
}

// Fetch Health info for footer
async function refreshHealth() {
  try {
    const res = await fetch("/healthz");
    if (res.ok) {
      const data = await res.json();
      document.getElementById("footerDbSize").textContent = `DB Size: ${data.db_size_mb} MB`;
    }
  } catch (e) {
    // ignore
  }
}

// Render Live Events Table (Safely using DOM / textContent)
function renderEventsTable() {
  const tbody = document.getElementById("eventsTableBody");
  tbody.innerHTML = "";

  const filtered = state.events.filter((ev) => {
    if (state.selectedHost && ev.host !== state.selectedHost) return false;
    if (state.categoryFilter && ev.category !== state.categoryFilter) return false;
    if (state.searchQuery) {
      const q = state.searchQuery.toLowerCase();
      const match =
        (ev.summary && ev.summary.toLowerCase().includes(q)) ||
        (ev.command_line && ev.command_line.toLowerCase().includes(q)) ||
        (ev.user_name && ev.user_name.toLowerCase().includes(q)) ||
        (ev.src_ip && ev.src_ip.toLowerCase().includes(q));
      if (!match) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 8;
    td.className = "empty-cell";
    td.textContent = "No events matching active filters.";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  filtered.slice(0, 100).forEach((ev) => {
    const tr = document.createElement("tr");
    tr.setAttribute("data-category", ev.category);
    tr.addEventListener("click", () => openEventDrawer(ev));

    // Time
    const tdTime = document.createElement("td");
    tdTime.textContent = formatTime(ev.timestamp);
    tdTime.style.fontFamily = "var(--font-mono)";

    // Host
    const tdHost = document.createElement("td");
    tdHost.textContent = ev.host || "-";

    // Channel
    const tdChannel = document.createElement("td");
    tdChannel.textContent = ev.channel || "-";

    // Event ID
    const tdId = document.createElement("td");
    tdId.textContent = ev.event_id;
    tdId.style.fontWeight = "bold";

    // Action
    const tdAction = document.createElement("td");
    tdAction.textContent = ev.action || "-";

    // User
    const tdUser = document.createElement("td");
    tdUser.textContent = ev.user_name || "-";

    // Src IP
    const tdIp = document.createElement("td");
    tdIp.textContent = ev.src_ip || "-";
    tdIp.style.fontFamily = "var(--font-mono)";

    // Process / Command
    const tdCmd = document.createElement("td");
    const cmdText = ev.command_line || ev.process_name || ev.summary || "-";
    tdCmd.textContent = cmdText.length > 70 ? cmdText.substring(0, 70) + "..." : cmdText;
    tdCmd.title = cmdText;

    tr.appendChild(tdTime);
    tr.appendChild(tdHost);
    tr.appendChild(tdChannel);
    tr.appendChild(tdId);
    tr.appendChild(tdAction);
    tr.appendChild(tdUser);
    tr.appendChild(tdIp);
    tr.appendChild(tdCmd);

    tbody.appendChild(tr);
  });
}

// Render Alerts Table
function renderAlertsTable() {
  const tbody = document.getElementById("alertsTableBody");
  tbody.innerHTML = "";

  const filtered = state.alerts.filter((a) => {
    if (state.alertSeverityFilter && a.severity !== state.alertSeverityFilter) return false;
    if (state.alertStatusFilter && a.status !== state.alertStatusFilter) return false;
    if (state.selectedHost && a.host !== state.selectedHost) return false;
    return true;
  });

  document.getElementById("alertsCountBadge").textContent = filtered.length;

  if (filtered.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 7;
    td.className = "empty-cell";
    td.textContent = "No alerts found matching filter criteria.";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  filtered.forEach((a) => {
    const tr = document.createElement("tr");
    if (a._justAdded) {
      tr.className = "flash-alert";
      delete a._justAdded;
    }
    tr.addEventListener("click", () => openAlertDrawer(a));

    // Time
    const tdTime = document.createElement("td");
    tdTime.textContent = formatTime(a.ts);
    tdTime.style.fontFamily = "var(--font-mono)";

    // Severity Pill
    const tdSev = document.createElement("td");
    const sevSpan = document.createElement("span");
    sevSpan.className = `sev-pill sev-${a.severity}`;
    sevSpan.textContent = a.severity;
    tdSev.appendChild(sevSpan);

    // Rule
    const tdRule = document.createElement("td");
    tdRule.textContent = `${a.rule_id} ${a.rule_name}`;
    tdRule.style.fontWeight = "600";

    // MITRE
    const tdMitre = document.createElement("td");
    if (a.mitre_technique) {
      const link = document.createElement("a");
      const cleanTech = a.mitre_technique.replace(".", "/");
      link.href = `https://attack.mitre.org/techniques/${cleanTech}/`;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = a.mitre_technique;
      link.style.color = "var(--accent-cyan)";
      link.style.textDecoration = "underline";
      link.addEventListener("click", (e) => e.stopPropagation());
      tdMitre.appendChild(link);
    } else {
      tdMitre.textContent = "-";
    }

    // Host
    const tdHost = document.createElement("td");
    tdHost.textContent = a.host || "-";

    // Entity
    const tdEntity = document.createElement("td");
    tdEntity.textContent = a.entity || "-";

    // Status Pill
    const tdStatus = document.createElement("td");
    const statusSpan = document.createElement("span");
    statusSpan.className = "status-pill";
    statusSpan.textContent = a.status;
    tdStatus.appendChild(statusSpan);

    tr.appendChild(tdTime);
    tr.appendChild(tdSev);
    tr.appendChild(tdRule);
    tr.appendChild(tdMitre);
    tr.appendChild(tdHost);
    tr.appendChild(tdEntity);
    tr.appendChild(tdStatus);

    tbody.appendChild(tr);
  });
}

// Fetch Initial Data via REST
async function fetchInitialData() {
  try {
    const [eventsRes, alertsRes] = await Promise.all([
      fetch("/api/events?limit=200"),
      fetch("/api/alerts?limit=100"),
    ]);

    if (eventsRes.ok) {
      state.events = await eventsRes.json();
      renderEventsTable();
      if (state.events.length > 0) {
        document.getElementById("footerLastIngest").textContent = `Last Ingest: ${formatTime(state.events[0].timestamp)}`;
      }
    }

    if (alertsRes.ok) {
      state.alerts = await alertsRes.json();
      renderAlertsTable();
    }

    await refreshStats();
    await refreshHealth();
  } catch (err) {
    console.error("Initial data load error:", err);
  }
}

// WebSocket Live Stream Management
function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/live`;
  const badge = document.getElementById("connectionBadge");
  const statusText = document.getElementById("statusText");

  badge.className = "status-badge badge-reconnecting";
  statusText.textContent = "CONNECTING";

  try {
    state.ws = new WebSocket(wsUrl);

    state.ws.onopen = () => {
      badge.className = "status-badge badge-live";
      statusText.textContent = "LIVE";
      state.wsReconnectDelay = 1000;
    };

    state.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === "hello") {
          console.log("WebSocket connected to SOC-Lite server:", msg);
        } else if (msg.type === "events") {
          if (!state.isFeedPaused) {
            const incoming = msg.data || [];
            if (incoming.length > 0) {
              // Prepend new incoming events to buffer
              state.events = [...incoming, ...state.events].slice(0, 200);
              renderEventsTable();
              document.getElementById("footerLastIngest").textContent = `Last Ingest: ${formatTime(incoming[0].timestamp)}`;
            }
          }
        } else if (msg.type === "alert") {
          const alert = msg.data;
          alert._justAdded = true;
          // Add to alert list if not already present
          const existingIdx = state.alerts.findIndex((a) => a.id === alert.id || a.dedupe_key === alert.dedupe_key);
          if (existingIdx >= 0) {
            state.alerts[existingIdx] = alert;
          } else {
            state.alerts.unshift(alert);
          }
          renderAlertsTable();
          playAlertBeep();
        } else if (msg.type === "stats") {
          if (msg.data.events_per_sec !== undefined) {
            document.getElementById("kpiRate").textContent = msg.data.events_per_sec.toFixed(1);
            document.getElementById("rateValue").textContent = `${msg.data.events_per_sec.toFixed(1)} /s`;
          }
        }
      } catch (err) {
        console.error("WebSocket message parse error:", err);
      }
    };

    state.ws.onclose = () => {
      badge.className = "status-badge badge-offline";
      statusText.textContent = "OFFLINE";
      // Backoff reconnect
      setTimeout(() => {
        state.wsReconnectDelay = Math.min(state.wsReconnectDelay * 1.5, 15000);
        connectWebSocket();
        fetchInitialData(); // Fill gaps after reconnect
      }, state.wsReconnectDelay);
    };

    state.ws.onerror = () => {
      state.ws.close();
    };
  } catch (e) {
    badge.className = "status-badge badge-offline";
    statusText.textContent = "OFFLINE";
  }
}

// Side Drawers logic
async function openAlertDrawer(alert) {
  state.activeAlert = alert;
  document.getElementById("drawerAlertTitle").textContent = `Alert #${alert.id || "-"}`;
  document.getElementById("drawerRuleName").textContent = `${alert.rule_id} - ${alert.rule_name}`;

  const sevBadge = document.getElementById("drawerSeverityBadge");
  sevBadge.className = `sev-pill sev-${alert.severity}`;
  sevBadge.textContent = alert.severity;

  const stBadge = document.getElementById("drawerStatusBadge");
  stBadge.textContent = alert.status;

  document.getElementById("drawerMitre").textContent = `${alert.mitre_tactic} // ${alert.mitre_technique || "None"}`;
  document.getElementById("drawerEntityHost").textContent = `${alert.entity || "N/A"} on ${alert.host}`;
  document.getElementById("drawerDescription").textContent = alert.description;
  document.getElementById("drawerAnalystNote").value = alert.note || "";

  // Fetch supporting events
  const container = document.getElementById("drawerSupportingEvents");
  container.innerHTML = "<em>Loading supporting events...</em>";

  if (alert.event_uids && alert.event_uids.length > 0) {
    try {
      const res = await fetch("/api/events/by-uids", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ uids: alert.event_uids }),
      });
      if (res.ok) {
        const evs = await res.json();
        container.innerHTML = "";
        evs.forEach((e) => {
          const item = document.createElement("div");
          item.className = "supporting-item";
          item.innerHTML = `<strong>${escapeHtml(formatTime(e.timestamp))} [ID ${e.event_id}]</strong> ${escapeHtml(e.summary)}`;
          item.addEventListener("click", () => openEventDrawer(e));
          container.appendChild(item);
        });
      }
    } catch (err) {
      container.textContent = "Failed to load supporting evidence.";
    }
  } else {
    container.textContent = "No specific event UIDs linked.";
  }

  document.getElementById("alertDrawer").classList.add("open");
}

function openEventDrawer(event) {
  state.activeEvent = event;
  document.getElementById("drawerEventSummary").textContent = event.summary || "Event Detail";
  document.getElementById("drawerEventJson").textContent = JSON.stringify(event, null, 2);
  document.getElementById("eventDrawer").classList.add("open");
}

async function updateActiveAlert(newStatus) {
  if (!state.activeAlert) return;
  const noteVal = document.getElementById("drawerAnalystNote").value;
  try {
    const res = await fetch(`/api/alerts/${state.activeAlert.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus, note: noteVal }),
    });
    if (res.ok) {
      const updated = await res.json();
      state.activeAlert = updated;
      const idx = state.alerts.findIndex((a) => a.id === updated.id);
      if (idx >= 0) state.alerts[idx] = updated;
      document.getElementById("drawerStatusBadge").textContent = updated.status;
      renderAlertsTable();
      refreshStats();
    }
  } catch (e) {
    alert("Failed to update alert status.");
  }
}

// Event Listeners Setup
function setupEventListeners() {
  document.getElementById("closeAlertDrawer").addEventListener("click", () => {
    document.getElementById("alertDrawer").classList.remove("open");
  });

  document.getElementById("closeEventDrawer").addEventListener("click", () => {
    document.getElementById("eventDrawer").classList.remove("open");
  });

  document.getElementById("btnAckAlert").addEventListener("click", () => updateActiveAlert("ack"));
  document.getElementById("btnCloseAlert").addEventListener("click", () => updateActiveAlert("closed"));
  document.getElementById("btnFpAlert").addEventListener("click", () => updateActiveAlert("false_positive"));

  // Pause Feed toggle
  const pauseBtn = document.getElementById("pauseBtn");
  pauseBtn.addEventListener("click", () => {
    state.isFeedPaused = !state.isFeedPaused;
    pauseBtn.textContent = state.isFeedPaused ? "RESUME FEED" : "PAUSE FEED";
    pauseBtn.className = state.isFeedPaused ? "btn btn-warning" : "btn btn-secondary";
  });

  // Audio Toggle
  const audioBtn = document.getElementById("audioToggleBtn");
  audioBtn.addEventListener("click", () => {
    state.audioEnabled = !state.audioEnabled;
    audioBtn.textContent = `AUDIO: ${state.audioEnabled ? "ON" : "OFF"}`;
    audioBtn.className = state.audioEnabled ? "btn btn-success" : "btn btn-secondary";
  });

  // Filters
  document.getElementById("rangeSelect").addEventListener("change", (e) => {
    state.selectedRangeMinutes = parseInt(e.target.value, 10);
    refreshStats();
  });

  document.getElementById("hostSelect").addEventListener("change", (e) => {
    state.selectedHost = e.target.value;
    renderEventsTable();
    renderAlertsTable();
  });

  document.getElementById("eventCategoryFilter").addEventListener("change", (e) => {
    state.categoryFilter = e.target.value;
    renderEventsTable();
  });

  let searchTimeout;
  document.getElementById("eventSearchInput").addEventListener("input", (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      state.searchQuery = e.target.value;
      renderEventsTable();
    }, 250);
  });

  document.getElementById("alertSeverityFilter").addEventListener("change", (e) => {
    state.alertSeverityFilter = e.target.value;
    renderAlertsTable();
  });

  document.getElementById("alertStatusFilter").addEventListener("change", (e) => {
    state.alertStatusFilter = e.target.value;
    renderAlertsTable();
  });
}

// App Initialization
window.addEventListener("DOMContentLoaded", () => {
  initCharts();
  setupEventListeners();
  fetchInitialData();
  connectWebSocket();

  // Periodic chart and stats refresh every 10 seconds
  setInterval(refreshStats, 10000);
  setInterval(refreshHealth, 30000);
});
