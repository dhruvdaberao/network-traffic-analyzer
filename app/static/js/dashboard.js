const APP = window.APP_BOOTSTRAP || {};
const page = APP.page || document.body.dataset.page;

const state = {
    charts: {},
    livePaused: false,
    packetPage: 1,
    packetPages: 1,
    packetFilters: {},
};

document.addEventListener("DOMContentLoaded", () => {
    bindCommonHandlers();
    initializePage();
    initializeSocket();
});

function initializePage() {
    refreshOverview();

    if (page === "overview") {
        loadOverviewPage();
    } else if (page === "live") {
        loadLivePage();
    } else if (page === "alerts") {
        loadAlertsPage();
    } else if (page === "packets") {
        loadPacketsPage();
    } else if (page === "settings") {
        loadSettingsPage();
    }
}

function initializeSocket() {
    if (!window.io) {
        showToast("Socket.IO client did not load. Real-time updates are unavailable.");
        return;
    }

    const socket = window.io();

    socket.on("capture_status", (payload) => {
        updateCaptureStatus(payload);
    });

    socket.on("stats_update", (payload) => {
        updateOverviewMetrics(payload);
        updateLiveMetrics(payload);
        if (page === "overview") {
            updateOverviewChartsFromPayload(payload);
        }
        stampRefreshTime();
    });

    socket.on("live_packet", (payload) => {
        if (page === "overview") {
            prependOverviewPacket(payload);
        }
        if (page === "live") {
            appendLiveFeedItem(payload);
        }
        if (page === "packets" && state.packetPage === 1 && !hasPacketFilters()) {
            prependPacketRow(payload);
        }
    });

    socket.on("alert_update", (payload) => {
        prependOverviewAlert(payload);
        if (page === "alerts") {
            prependAlertRow(payload);
        }
        showToast(`${payload.alert_type}: ${payload.reason}`);
    });
}

function bindCommonHandlers() {
    const liveToggle = document.getElementById("toggle-live-feed");
    if (liveToggle) {
        liveToggle.addEventListener("click", () => {
            state.livePaused = !state.livePaused;
            liveToggle.textContent = state.livePaused ? "Resume Feed" : "Pause Feed";
        });
    }

    const liveFilter = document.getElementById("live-protocol-filter");
    if (liveFilter) {
        liveFilter.addEventListener("change", async () => {
            const packets = await fetchJson("/api/packets?per_page=20");
            renderLiveFeed(
                (packets.items || []).filter((item) =>
                    liveFilter.value === "all" ? true : item.protocol === liveFilter.value
                )
            );
        });
    }
}

async function loadOverviewPage() {
    const [overview, protocolData, bandwidthData, talkerData, packetData, alertData] = await Promise.all([
        fetchJson("/api/overview"),
        fetchJson("/api/traffic/protocol-distribution"),
        fetchJson("/api/traffic/bandwidth"),
        fetchJson("/api/traffic/top-talkers"),
        fetchJson("/api/packets?per_page=8"),
        fetchJson("/api/alerts?limit=8"),
    ]);

    updateOverviewMetrics(overview);
    renderOverviewCharts(protocolData.items || [], bandwidthData, talkerData);
    renderOverviewPacketTable(packetData.items || []);
    renderOverviewAlertTable(alertData.items || []);
}

async function loadLivePage() {
    const [overview, packets] = await Promise.all([
        fetchJson("/api/overview"),
        fetchJson("/api/packets?per_page=20"),
    ]);
    updateOverviewMetrics(overview);
    updateLiveMetrics(overview);
    renderLiveFeed(packets.items || []);
}

async function loadAlertsPage() {
    const filter = document.getElementById("alert-status-filter");
    if (filter && !filter.dataset.bound) {
        filter.dataset.bound = "true";
        filter.addEventListener("change", () => loadAlertsPage());
    }
    const status = filter ? filter.value : "all";
    const data = await fetchJson(`/api/alerts?status=${encodeURIComponent(status)}`);
    renderAlertsTable(data.items || []);
}

async function loadPacketsPage() {
    const form = document.getElementById("packet-filter-form");
    const resetButton = document.getElementById("packet-filter-reset");
    const prev = document.getElementById("packets-prev-page");
    const next = document.getElementById("packets-next-page");

    if (form && !form.dataset.bound) {
        form.dataset.bound = "true";
        form.addEventListener("submit", (event) => {
            event.preventDefault();
            state.packetPage = 1;
            state.packetFilters = readPacketFilters();
            fetchPacketTable();
        });
    }

    if (resetButton && !resetButton.dataset.bound) {
        resetButton.dataset.bound = "true";
        resetButton.addEventListener("click", () => {
            document.getElementById("packet-protocol-filter").value = "all";
            document.getElementById("packet-src-filter").value = "";
            document.getElementById("packet-dst-filter").value = "";
            document.getElementById("packet-search-filter").value = "";
            state.packetFilters = {};
            state.packetPage = 1;
            fetchPacketTable();
        });
    }

    if (prev && !prev.dataset.bound) {
        prev.dataset.bound = "true";
        prev.addEventListener("click", () => {
            if (state.packetPage > 1) {
                state.packetPage -= 1;
                fetchPacketTable();
            }
        });
    }

    if (next && !next.dataset.bound) {
        next.dataset.bound = "true";
        next.addEventListener("click", () => {
            if (state.packetPage < state.packetPages) {
                state.packetPage += 1;
                fetchPacketTable();
            }
        });
    }

    state.packetFilters = readPacketFilters();
    await fetchPacketTable();
}

async function loadSettingsPage() {
    const startLive = document.getElementById("start-live-btn");
    const startDemo = document.getElementById("start-demo-btn");
    const stopCapture = document.getElementById("stop-capture-btn");
    const clearData = document.getElementById("clear-data-btn");
    const thresholdForm = document.getElementById("threshold-form");

    if (startLive && !startLive.dataset.bound) {
        startLive.dataset.bound = "true";
        startLive.addEventListener("click", async () => {
            const iface = document.getElementById("interface-select").value;
            const response = await postJson("/api/capture/start", { interface: iface });
            updateCaptureStatus(response.status || response);
            showToast(response.message || "Live capture started.");
        });
    }

    if (startDemo && !startDemo.dataset.bound) {
        startDemo.dataset.bound = "true";
        startDemo.addEventListener("click", async () => {
            const response = await postJson("/api/capture/demo-start", {});
            updateCaptureStatus(response.status || response);
            showToast(response.message || "Demo mode started.");
        });
    }

    if (stopCapture && !stopCapture.dataset.bound) {
        stopCapture.dataset.bound = "true";
        stopCapture.addEventListener("click", async () => {
            const response = await postJson("/api/capture/stop", {});
            updateCaptureStatus(response.status || response);
            showToast(response.message || "Capture stopped.");
        });
    }

    if (clearData && !clearData.dataset.bound) {
        clearData.dataset.bound = "true";
        clearData.addEventListener("click", async () => {
            const response = await postJson("/api/settings/clear-data", {});
            showToast(response.message || "Stored data cleared.");
            refreshOverview();
        });
    }

    if (thresholdForm && !thresholdForm.dataset.bound) {
        thresholdForm.dataset.bound = "true";
        thresholdForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            const payload = Object.fromEntries(new FormData(thresholdForm).entries());
            const response = await postJson("/api/settings/thresholds", payload);
            showToast(response.message || "Thresholds updated.");
        });
    }
}

async function refreshOverview() {
    const overview = await fetchJson("/api/overview");
    updateOverviewMetrics(overview);
}

async function fetchPacketTable() {
    const params = new URLSearchParams({
        page: String(state.packetPage),
        per_page: String(APP.defaultPageSize || 25),
    });

    Object.entries(state.packetFilters).forEach(([key, value]) => {
        if (value) {
            params.set(key, value);
        }
    });

    const data = await fetchJson(`/api/packets?${params.toString()}`);
    renderPacketTable(data.items || []);
    updatePacketPagination(data.pagination || {});
}

function readPacketFilters() {
    return {
        protocol: document.getElementById("packet-protocol-filter")?.value || "all",
        src_ip: document.getElementById("packet-src-filter")?.value.trim() || "",
        dst_ip: document.getElementById("packet-dst-filter")?.value.trim() || "",
        search: document.getElementById("packet-search-filter")?.value.trim() || "",
    };
}

function hasPacketFilters() {
    return Object.values(state.packetFilters || {}).some((value) => value && value !== "all");
}

function updateOverviewMetrics(payload = {}) {
    setText("metric-total-packets", formatNumber(payload.total_packets));
    setText("metric-total-bytes", formatBytes(payload.total_bytes || 0));
    setText("metric-active-alerts", formatNumber(payload.active_alerts));
    setText("metric-bandwidth", formatBits(payload.current_bandwidth_bps || 0));
    setText("metric-interface", payload.selected_interface || "Not selected");
    setText("metric-status", titleCase(payload.capture_status || "stopped"));
    setText("capture-mode-chip", titleCase(payload.capture_mode || "idle"));
    setText("selected-interface-chip", payload.selected_interface || "Not selected");
}

function updateLiveMetrics(payload = {}) {
    setText("live-total-packets", formatNumber(payload.total_packets));
    setText("live-bandwidth", formatBits(payload.current_bandwidth_bps || 0));
    setText("live-alert-count", formatNumber(payload.active_alerts));
    setText("live-dominant-protocol", payload.dominant_protocol || "N/A");
}

function updateCaptureStatus(payload = {}) {
    const status = (payload.status || "stopped").toLowerCase();
    const mode = titleCase(payload.mode || "idle");

    applyStatusChip("capture-status-pill", status, titleCase(status));
    applyStatusChip("settings-status-pill", status, titleCase(status));
    setText("capture-status-message", payload.message || "Capture idle.");
    setText("settings-status-message", payload.message || "Capture idle.");
    setText("selected-interface-chip", payload.interface || "Not selected");
    setText("metric-interface", payload.interface || "Not selected");
    setText("metric-status", titleCase(status));
    setText("capture-mode-chip", mode);
}

function renderOverviewCharts(protocolItems, bandwidthData, talkerData) {
    const labels = bandwidthData.labels || [];
    const packetValues = bandwidthData.packets || [];
    const bandwidthValues = bandwidthData.bandwidth || [];
    const talkers = talkerData.talkers || [];

    state.charts.packetTrend = createOrUpdateChart(state.charts.packetTrend, "packets-trend-chart", "line", {
        labels,
        datasets: [{
            label: "Packets",
            data: packetValues,
            borderColor: "#63c7df",
            backgroundColor: "rgba(99, 199, 223, 0.18)",
            fill: true,
            tension: 0.3,
        }],
    });

    state.charts.bandwidth = createOrUpdateChart(state.charts.bandwidth, "bandwidth-chart", "line", {
        labels,
        datasets: [{
            label: "Bandwidth (bps)",
            data: bandwidthValues,
            borderColor: "#69b98f",
            backgroundColor: "rgba(105, 185, 143, 0.14)",
            fill: true,
            tension: 0.3,
        }],
    });

    state.charts.protocol = createOrUpdateChart(state.charts.protocol, "protocol-chart", "doughnut", {
        labels: protocolItems.map((item) => item.label),
        datasets: [{
            data: protocolItems.map((item) => item.value),
            backgroundColor: ["#4db4cf", "#69b98f", "#e3b268", "#db6a6a", "#86a7ff", "#8f87ff", "#c58cff"],
            borderWidth: 0,
        }],
    });

    state.charts.talkers = createOrUpdateChart(state.charts.talkers, "talkers-chart", "bar", {
        labels: talkers.map((item) => item.label),
        datasets: [{
            label: "Bytes",
            data: talkers.map((item) => item.value),
            backgroundColor: "rgba(77, 180, 207, 0.48)",
            borderRadius: 10,
        }],
    });
}

function updateOverviewChartsFromPayload(payload) {
    if (!document.getElementById("packets-trend-chart")) {
        return;
    }
    if (state.charts.packetTrend) {
        state.charts.packetTrend.data.labels = payload.packet_trend?.labels || [];
        state.charts.packetTrend.data.datasets[0].data = payload.packet_trend?.values || [];
        state.charts.packetTrend.update();
    }
    if (state.charts.bandwidth) {
        state.charts.bandwidth.data.labels = payload.bandwidth_trend?.labels || [];
        state.charts.bandwidth.data.datasets[0].data = payload.bandwidth_trend?.values || [];
        state.charts.bandwidth.update();
    }
    if (state.charts.protocol && payload.protocol_distribution) {
        state.charts.protocol.data.labels = payload.protocol_distribution.map((item) => item.label);
        state.charts.protocol.data.datasets[0].data = payload.protocol_distribution.map((item) => item.value);
        state.charts.protocol.update();
    }
    if (state.charts.talkers && payload.top_talkers) {
        state.charts.talkers.data.labels = payload.top_talkers.map((item) => item.label);
        state.charts.talkers.data.datasets[0].data = payload.top_talkers.map((item) => item.value);
        state.charts.talkers.update();
    }
}

function renderOverviewPacketTable(items) {
    const body = document.getElementById("overview-packets-body");
    if (!body) return;
    body.innerHTML = items.length
        ? items.map((item) => overviewPacketRow(item)).join("")
        : `<tr><td colspan="4" class="empty-state">Waiting for packet data.</td></tr>`;
}

function renderOverviewAlertTable(items) {
    const body = document.getElementById("overview-alerts-body");
    if (!body) return;
    body.innerHTML = items.length
        ? items.map((item) => overviewAlertRow(item)).join("")
        : `<tr><td colspan="4" class="empty-state">No alerts yet.</td></tr>`;
}

function prependOverviewPacket(item) {
    const body = document.getElementById("overview-packets-body");
    if (!body) return;
    removeEmptyState(body);
    body.insertAdjacentHTML("afterbegin", overviewPacketRow(item));
    trimRows(body, 8);
}

function prependOverviewAlert(item) {
    const body = document.getElementById("overview-alerts-body");
    if (!body) return;
    removeEmptyState(body);
    body.insertAdjacentHTML("afterbegin", overviewAlertRow(item));
    trimRows(body, 8);
}

function renderLiveFeed(items) {
    const feed = document.getElementById("live-feed");
    if (!feed) return;
    feed.innerHTML = items.length
        ? items.map((item) => liveFeedCard(item)).join("")
        : `<div class="feed-empty">Feed is waiting for incoming packets.</div>`;
}

function appendLiveFeedItem(item) {
    if (state.livePaused) return;
    const selectedProtocol = document.getElementById("live-protocol-filter")?.value || "all";
    if (selectedProtocol !== "all" && item.protocol !== selectedProtocol) return;
    const feed = document.getElementById("live-feed");
    if (!feed) return;
    removeEmptyState(feed);
    feed.insertAdjacentHTML("afterbegin", liveFeedCard(item));
    trimChildren(feed, 30);
}

function renderAlertsTable(items) {
    const body = document.getElementById("alerts-table-body");
    if (!body) return;
    body.innerHTML = items.length
        ? items.map((item) => alertRow(item)).join("")
        : `<tr><td colspan="8" class="empty-state">No alerts available.</td></tr>`;
    bindReviewButtons();
}

function prependAlertRow(item) {
    const body = document.getElementById("alerts-table-body");
    if (!body) return;
    removeEmptyState(body);
    body.insertAdjacentHTML("afterbegin", alertRow(item));
    trimRows(body, 40);
    bindReviewButtons();
}

function bindReviewButtons() {
    document.querySelectorAll("[data-review-alert]").forEach((button) => {
        button.onclick = async () => {
            const id = button.dataset.reviewAlert;
            const response = await postJson(`/api/alerts/${id}/review`, {});
            button.disabled = true;
            button.textContent = "Reviewed";
            showToast(`Alert ${response.item.id} marked as reviewed.`);
            loadAlertsPage();
        };
    });
}

function renderPacketTable(items) {
    const body = document.getElementById("packets-table-body");
    if (!body) return;
    body.innerHTML = items.length
        ? items.map((item) => packetRow(item)).join("")
        : `<tr><td colspan="7" class="empty-state">No packet records available.</td></tr>`;
}

function prependPacketRow(item) {
    const body = document.getElementById("packets-table-body");
    if (!body) return;
    removeEmptyState(body);
    body.insertAdjacentHTML("afterbegin", packetRow(item));
    trimRows(body, APP.defaultPageSize || 25);
}

function updatePacketPagination(pagination) {
    state.packetPages = pagination.pages || 1;
    setText("packets-page-label", `Page ${pagination.page || 1} of ${pagination.pages || 1}`);
    const prev = document.getElementById("packets-prev-page");
    const next = document.getElementById("packets-next-page");
    if (prev) prev.disabled = !pagination.has_prev;
    if (next) next.disabled = !pagination.has_next;
}

function overviewPacketRow(item) {
    return `<tr><td>${formatTime(item.timestamp)}</td><td>${protocolBadge(item.protocol)}</td><td>${escapeHtml(item.src_ip)} → ${escapeHtml(item.dst_ip)}</td><td>${escapeHtml(item.summary)}</td></tr>`;
}

function overviewAlertRow(item) {
    return `<tr><td>${severityBadge(item.severity)}</td><td>${escapeHtml(item.alert_type)}</td><td>${escapeHtml(item.src_ip || "-")}</td><td>${escapeHtml(item.reason)}</td></tr>`;
}

function liveFeedCard(item) {
    return `
        <article class="feed-item">
            <div class="feed-item-header">
                <div class="feed-summary">${escapeHtml(item.summary)}</div>
                ${protocolBadge(item.protocol)}
            </div>
            <div class="feed-meta">${formatTime(item.timestamp)} | ${escapeHtml(item.src_ip || "-")} → ${escapeHtml(item.dst_ip || "-")} | ${formatBytes(item.length || 0)}</div>
        </article>
    `;
}

function alertRow(item) {
    const reviewAction = item.status === "Reviewed"
        ? `<span class="muted-pill">Reviewed</span>`
        : `<button class="action-button secondary" data-review-alert="${item.id}">Mark Reviewed</button>`;
    return `
        <tr>
            <td>${formatDateTime(item.timestamp)}</td>
            <td>${severityBadge(item.severity)}</td>
            <td>${escapeHtml(item.alert_type)}</td>
            <td>${escapeHtml(item.src_ip || "-")}</td>
            <td>${escapeHtml(item.dst_ip || "-")}</td>
            <td>${escapeHtml(item.reason)}</td>
            <td>${escapeHtml(item.status)}</td>
            <td>${reviewAction}</td>
        </tr>
    `;
}

function packetRow(item) {
    return `
        <tr>
            <td>${formatDateTime(item.timestamp)}</td>
            <td>${protocolBadge(item.protocol)}</td>
            <td>${escapeHtml(item.src_ip || "-")}${item.src_port ? `:${item.src_port}` : ""}</td>
            <td>${escapeHtml(item.dst_ip || "-")}${item.dst_port ? `:${item.dst_port}` : ""}</td>
            <td>${formatBytes(item.length || 0)}</td>
            <td>${escapeHtml(item.direction || "unknown")}</td>
            <td>${escapeHtml(item.summary)}</td>
        </tr>
    `;
}

function protocolBadge(protocol = "Unknown") {
    const slug = protocol.toLowerCase().replace(/[^\w]+/g, "-");
    return `<span class="protocol-badge ${slug}">${escapeHtml(protocol)}</span>`;
}

function severityBadge(severity = "Low") {
    return `<span class="severity-badge ${severity.toLowerCase()}">${escapeHtml(severity)}</span>`;
}

function applyStatusChip(id, status, label) {
    const element = document.getElementById(id);
    if (!element) return;
    element.className = `status-chip ${status}`;
    element.textContent = label;
}

function createOrUpdateChart(existingChart, canvasId, type, data) {
    if (!window.Chart) return null;
    const canvas = document.getElementById(canvasId);
    if (!canvas) return existingChart;

    const options = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { labels: { color: "#d8e0e8" } },
        },
        scales: type === "doughnut" ? {} : {
            x: {
                ticks: { color: "#9fb0c3" },
                grid: { color: "rgba(255,255,255,0.04)" },
            },
            y: {
                ticks: { color: "#9fb0c3" },
                grid: { color: "rgba(255,255,255,0.04)" },
            },
        },
    };

    if (existingChart) {
        existingChart.data = data;
        existingChart.update();
        return existingChart;
    }

    return new window.Chart(canvas, { type, data, options });
}

async function fetchJson(url) {
    const response = await fetch(url);
    if (!response.ok) {
        showToast(`Request failed: ${url}`);
        throw new Error(`Request failed: ${url}`);
    }
    return response.json();
}

async function postJson(url, payload) {
    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    });
    if (!response.ok) {
        showToast(`Request failed: ${url}`);
        throw new Error(`Request failed: ${url}`);
    }
    return response.json();
}

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
}

function removeEmptyState(node) {
    const empty = node.querySelector(".empty-state, .feed-empty");
    if (empty) empty.remove();
}

function trimRows(body, maxRows) {
    while (body.children.length > maxRows) {
        body.removeChild(body.lastElementChild);
    }
}

function trimChildren(node, maxChildren) {
    while (node.children.length > maxChildren) {
        node.removeChild(node.lastElementChild);
    }
}

function showToast(message) {
    const toast = document.getElementById("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.classList.remove("hidden");
    window.clearTimeout(showToast.timeoutId);
    showToast.timeoutId = window.setTimeout(() => {
        toast.classList.add("hidden");
    }, 3400);
}

function stampRefreshTime() {
    setText("last-refresh-chip", new Date().toLocaleTimeString());
}

function formatDateTime(value) {
    if (!value) return "-";
    return new Date(value).toLocaleString();
}

function formatTime(value) {
    if (!value) return "-";
    return new Date(value).toLocaleTimeString();
}

function formatBytes(value) {
    const units = ["B", "KB", "MB", "GB"];
    let amount = Number(value || 0);
    let index = 0;
    while (amount >= 1024 && index < units.length - 1) {
        amount /= 1024;
        index += 1;
    }
    return `${amount.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function formatBits(value) {
    const units = ["bps", "Kbps", "Mbps", "Gbps"];
    let amount = Number(value || 0);
    let index = 0;
    while (amount >= 1000 && index < units.length - 1) {
        amount /= 1000;
        index += 1;
    }
    return `${amount.toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}

function formatNumber(value) {
    return Number(value || 0).toLocaleString();
}

function titleCase(value) {
    return String(value || "")
        .replace(/[_-]+/g, " ")
        .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
