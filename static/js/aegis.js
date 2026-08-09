/**
 * AegisWAF — Security Command Center Frontend Logic
 */

document.addEventListener("DOMContentLoaded", function () {
    initNavigationTabs();
    initInspector();
    initSOCDashboard();
    initRuleInspector();
});

/* -------------------------------------------------------------------------- */
/* Navigation Tab System                                                      */
/* -------------------------------------------------------------------------- */
function initNavigationTabs() {
    const tabButtons = document.querySelectorAll(".tab-btn");
    const tabContents = document.querySelectorAll(".tab-content");

    tabButtons.forEach(button => {
        button.addEventListener("click", () => {
            const targetTab = button.getAttribute("data-tab");

            tabButtons.forEach(btn => btn.classList.remove("active"));
            tabContents.forEach(content => content.classList.remove("active"));

            button.classList.add("active");
            const activeContent = document.getElementById(targetTab);
            if (activeContent) {
                activeContent.classList.add("active");
            }

            if (targetTab === "soc-tab") {
                loadAnalytics();
                loadThreatLogs(1);
            }
        });
    });
}

/* -------------------------------------------------------------------------- */
/* Live Payload Inspector & Preset Handler                                    */
/* -------------------------------------------------------------------------- */
const PRESETS = {
    sqli: { method: "GET", uri: "/search?q=' OR '1'='1'; DROP TABLE users;--", body: "" },
    xss: { method: "POST", uri: "/comment/add", body: "<script>alert('XSS_Exfiltration')</script>" },
    obfuscated: { method: "GET", uri: "/products?filter=%27%20OR%20%271%27%3D%271", body: "" },
    rce: { method: "GET", uri: "/ping?host=127.0.0.1; cat /etc/passwd", body: "" },
    ssrf: { method: "GET", uri: "/fetch?url=http://169.254.169.254/latest/meta-data/", body: "" },
    safe: { method: "POST", uri: "/api/v1/checkout", body: '{"item_id": 104, "quantity": 2}' }
};

function loadPreset(type) {
    if (PRESETS[type]) {
        document.getElementById("req-method").value = PRESETS[type].method;
        document.getElementById("req-uri").value = PRESETS[type].uri;
        document.getElementById("req-body").value = PRESETS[type].body;
    }
}

function initInspector() {
    const inspectBtn = document.getElementById("inspect-btn");
    if (!inspectBtn) return;

    inspectBtn.addEventListener("click", function () {
        const method = document.getElementById("req-method").value;
        const uri = document.getElementById("req-uri").value.trim();
        const postData = document.getElementById("req-body").value.trim();
        const userInput = uri || postData || "/";

        const btnText = document.getElementById("btn-text");
        btnText.textContent = "Scanning Payload...";
        inspectBtn.disabled = true;

        fetch("/api/v1/inspect", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                method: method,
                uri: uri,
                post_data: postData,
                user_request: userInput
            })
        })
        .then(res => res.json())
        .then(data => {
            btnText.textContent = "Analyze Payload";
            inspectBtn.disabled = false;
            renderInspectionResult(data);
        })
        .catch(err => {
            console.error("Inspection error:", err);
            btnText.textContent = "Analyze Payload";
            inspectBtn.disabled = false;
        });
    });
}

function renderInspectionResult(data) {
    const container = document.getElementById("inspection-results");
    container.classList.add("active");

    const banner = document.getElementById("verdict-banner");
    const icon = document.getElementById("verdict-icon");
    const title = document.getElementById("verdict-title");
    const desc = document.getElementById("verdict-desc");
    const riskVal = document.getElementById("risk-value");
    const riskBar = document.getElementById("risk-bar-fill");
    const remediationText = document.getElementById("remediation-text");

    banner.className = "verdict-banner";

    if (data.status === "BLOCKED") {
        banner.classList.add("blocked");
        icon.textContent = "🚨";
        title.textContent = `BLOCKED — ${data.attack_type}`;
        desc.textContent = "Layer-1 Signature Engine neutralized threat immediately.";
        riskBar.style.background = "#ef4444";
    } else if (data.status === "ANOMALY") {
        banner.classList.add("anomaly");
        icon.textContent = "🤖";
        title.textContent = `ANOMALY DETECTED — ${data.attack_type}`;
        desc.textContent = "Obfuscated vector caught by Layer-2 AI Anomaly Model.";
        riskBar.style.background = "#f59e0b";
    } else {
        banner.classList.add("safe");
        icon.textContent = "🛡️";
        title.textContent = "SAFE — Clean Request Verified";
        desc.textContent = "Request cleared both Layer-1 and Layer-2 inspection.";
        riskBar.style.background = "#10b981";
    }

    riskVal.textContent = `${data.risk_score}%`;
    riskBar.style.width = `${data.risk_score}%`;
    remediationText.textContent = data.remediation;

    // Render Feature Radar Bars
    const feats = data.extracted_features;
    renderFeatureBar("feat-uri-len", "URI Length", feats.URI_Length, 200);
    renderFeatureBar("feat-entropy", "Shannon Entropy", feats.URI_Entropy.toFixed(2), 8.0);
    renderFeatureBar("feat-ratio", "Numeric/Text Ratio", feats.Numeric_Text_Ratio.toFixed(2), 2.0);
    renderFeatureBar("feat-chars", "Special Char Count", feats.Special_Char_Count, 30);
}

function renderFeatureBar(elementId, label, val, maxVal) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const pct = Math.min((val / maxVal) * 100, 100);
    el.innerHTML = `
        <div class="feature-info">
            <span>${label}</span>
            <span>${val}</span>
        </div>
        <div class="feature-track">
            <div class="feature-fill" style="width: ${pct}%"></div>
        </div>
    `;
}

/* -------------------------------------------------------------------------- */
/* SOC Dashboard & Analytics Fetcher                                          */
/* -------------------------------------------------------------------------- */
let currentFilter = "ALL";
let currentSearch = "";

function initSOCDashboard() {
    loadAnalytics();

    const searchInput = document.getElementById("log-search");
    if (searchInput) {
        searchInput.addEventListener("input", function (e) {
            currentSearch = e.target.value.trim();
            loadThreatLogs(1);
        });
    }

    const exportBtn = document.getElementById("export-csv-btn");
    if (exportBtn) {
        exportBtn.addEventListener("click", function () {
            window.location.href = "/api/v1/export/csv";
        });
    }
}

function loadAnalytics() {
    fetch("/api/v1/analytics")
        .then(res => res.json())
        .then(data => {
            document.getElementById("stat-total").textContent = data.total_scanned;
            document.getElementById("stat-blocked").textContent = data.blocked_count + data.anomaly_count;
            document.getElementById("stat-rate").textContent = data.threat_mitigation_rate;
            document.getElementById("stat-latency").textContent = data.avg_latency;

            renderAttackDistribution(data.attack_distribution);
        })
        .catch(err => console.error("Analytics fetch error:", err));
}

function renderAttackDistribution(distribution) {
    const container = document.getElementById("distribution-bars");
    if (!container) return;
    container.innerHTML = "";

    const entries = Object.entries(distribution);
    if (entries.length === 0) {
        container.innerHTML = "<p style='color: var(--text-muted)'>No attack data recorded yet.</p>";
        return;
    }

    const totalAttacks = entries.reduce((acc, curr) => acc + curr[1], 0);

    entries.forEach(([type, count]) => {
        const pct = Math.round((count / totalAttacks) * 100);
        const item = document.createElement("div");
        item.className = "feature-bar-item";
        item.style.marginBottom = "0.75rem";
        item.innerHTML = `
            <div class="feature-info">
                <span>${type}</span>
                <span>${count} (${pct}%)</span>
            </div>
            <div class="feature-track">
                <div class="feature-fill" style="width: ${pct}%; background: var(--accent-violet)"></div>
            </div>
        `;
        container.appendChild(item);
    });
}

function setFilter(status) {
    currentFilter = status;
    document.querySelectorAll(".filter-btn").forEach(btn => {
        btn.classList.toggle("active", btn.getAttribute("data-status") === status);
    });
    loadThreatLogs(1);
}

function loadThreatLogs(page) {
    const tableBody = document.getElementById("log-table-body");
    if (!tableBody) return;

    fetch(`/api/v1/logs?page=${page}&limit=15&status=${currentFilter}&search=${encodeURIComponent(currentSearch)}`)
        .then(res => res.json())
        .then(data => {
            tableBody.innerHTML = "";

            if (data.logs.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No matching threat logs found.</td></tr>`;
                return;
            }

            data.logs.forEach(log => {
                const tr = document.createElement("tr");
                const badgeClass = log.final_status.toLowerCase();
                
                tr.innerHTML = `
                    <td>#${log.id}</td>
                    <td>${log.timestamp}</td>
                    <td>${log.client_ip}</td>
                    <td><span class="badge ${badgeClass}">${log.final_status}</span></td>
                    <td>${log.attack_type}</td>
                    <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(log.user_input)}</td>
                    <td>${log.risk_score}%</td>
                `;
                tableBody.appendChild(tr);
            });
        })
        .catch(err => console.error("Logs fetch error:", err));
}

function initRuleInspector() {
    fetch("/api/v1/rules")
        .then(res => res.json())
        .then(data => {
            const ruleCountEl = document.getElementById("rule-sig-count");
            if (ruleCountEl) {
                ruleCountEl.textContent = data.signature_rules.malicious_patterns + data.signature_rules.obfuscation_patterns;
            }
        })
        .catch(err => console.error("Rules fetch error:", err));
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}
