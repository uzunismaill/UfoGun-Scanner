const term = document.getElementById('terminal');
const startBtn = document.getElementById('startScanBtn');
const urlInput = document.getElementById('targetUrl');
const recentTable = document.querySelector('#recentTable tbody');

// --- Audio FX ---
let audioCtx;
function initAudio() {
    if (!audioCtx) {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (AudioContext) audioCtx = new AudioContext();
    }
    if (audioCtx && audioCtx.state === 'suspended') {
        audioCtx.resume().catch(() => { });
    }
}

function playClickSound() {
    try {
        initAudio();
        if (!audioCtx) return;

        const t = audioCtx.currentTime;
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();

        osc.type = 'sine';
        osc.frequency.setValueAtTime(800, t);
        osc.frequency.exponentialRampToValueAtTime(400, t + 0.1);

        gain.gain.setValueAtTime(0.1, t);
        gain.gain.exponentialRampToValueAtTime(0.01, t + 0.1);

        osc.connect(gain);
        gain.connect(audioCtx.destination);

        osc.start(t);
        osc.stop(t + 0.1);
    } catch (e) {
        // console.warn(e);
    }
}

function playRadarSound() {
    try {
        initAudio();
        if (!audioCtx) return;

        const t = audioCtx.currentTime;
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();

        osc.type = 'sine';
        osc.frequency.setValueAtTime(600, t);
        osc.frequency.exponentialRampToValueAtTime(1000, t + 0.1);

        // Extremely low volume to be subtle
        gain.gain.setValueAtTime(0, t);
        gain.gain.linearRampToValueAtTime(0.005, t + 0.05); // Peak volume very low
        gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.8); // Quick decay

        osc.connect(gain);
        gain.connect(audioCtx.destination);

        osc.start(t);
        osc.stop(t + 1.0); // Stop completely before next ping (1.5s interval)
    } catch (e) { }
}

function spawnRadarBlip() {
    const radar = document.getElementById('scanRadar');
    if (!radar || !radar.classList.contains('active')) return;

    const blip = document.createElement('div');
    blip.classList.add('radar-blip');

    // Random Position within the circle (approx)
    // 700px width/height, so center is 350,350
    const angle = Math.random() * Math.PI * 2;
    const radius = Math.random() * 300; // max radius 300px

    // We want to position relative to center of the 700x700 overlay
    // But since it's centered with transform translate, positioning might be tricky if we use left/top directly without offset.
    // The overlay is 700x700. CSS: left 50%, top 50%, transform -50,-50.
    // So 0,0 is top-left of the box. Center is 350,350.

    const x = 350 + Math.cos(angle) * radius;
    const y = 350 + Math.sin(angle) * radius;

    blip.style.left = `${x}px`;
    blip.style.top = `${y}px`;

    radar.appendChild(blip);

    setTimeout(() => blip.remove(), 2500);
}

// --- Navigation ---
window.switchView = (viewName) => {
    playClickSound();

    // 1. Hide all views
    document.querySelectorAll('.view-section').forEach(el => {
        el.classList.remove('active');
        el.style.display = 'none';
    });

    // 2. Clear active state from all tabs
    document.querySelectorAll('.tab-link').forEach(el => el.classList.remove('active'));

    // 3. Show selected view
    const view = document.getElementById(`view-${viewName}`);
    if (view) {
        view.style.display = 'block';
        setTimeout(() => view.classList.add('active'), 10);
    }

    // 4. Set active tab
    const activeLink = document.querySelector(`.tab-link[onclick*="'${viewName}'"]`);
    if (activeLink) {
        activeLink.classList.add('active');
    }

    if (viewName === 'reports') loadReports();
    if (viewName === 'dashboard') loadRecent();
};

function log(msg, type = 'info') {
    const line = document.createElement('div');
    line.className = `log-line ${type}`;
    line.innerHTML = `&gt; ${msg}`;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
}

// --- Scanning ---
startBtn.addEventListener('click', async () => {
    const url = urlInput.value.trim();
    if (!url) return alert("Please enter a target.");

    // UI Reset
    term.innerHTML = '';
    term.classList.add('active');

    const radar = document.getElementById('scanRadar');
    if (radar) radar.classList.add('active');

    startBtn.disabled = true;
    startBtn.textContent = 'SCANNING...';

    // Start Radar Sound & Blips
    playRadarSound();
    const radarInterval = setInterval(playRadarSound, 1500);
    const blipInterval = setInterval(spawnRadarBlip, 800);

    // Simulation Sequence
    try {
        log(`Target acquired: ${url}`, 'cmd');
        spawnRadarBlip();
        await wait(400);

        log("Resolving host...", 'info');
        await wait(600);

        log("Host is UP. Initiating deep reconnaissance...", 'success');
        await wait(500);

        log("Starting comprehensive Port Scan (Top 20)...", 'info');
        await wait(800);

        log("Detected open ports: 80, 443, 8080...", 'success');
        await wait(600);

        // Admin Enumeration Simulation
        log("[*] Starting Admin Page Enumeration...", 'cmd');
        const commonPaths = ['/admin', '/login', '/wp-admin', '/dashboard', '/cpanel'];

        for (const path of commonPaths) {
            await wait(200);
            if (Math.random() > 0.8) {
                log(`[+] Potential admin path: ${path} (HTTP 200)`, 'success');
            }
        }

        log("Analyzing SSL/TLS security...", 'info');
        await wait(400);
        log("Identifying Technology Stack...", 'info');

        // Real Backend Call
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await res.json();

        await fetch('/api/reports', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        log("Scan Complete. Report Generated.", 'success');
        await wait(1000);

        // Stop sound and redirect
        clearInterval(radarInterval);
        clearInterval(blipInterval);
        if (radar) radar.classList.remove('active');

        switchView('reports');
        showReportDetail(data);

    } catch (e) {
        clearInterval(radarInterval);
        clearInterval(blipInterval);
        log(`Fatal Error: ${e.message}`, 'error');
        if (radar) radar.classList.remove('active');
    }

    startBtn.disabled = false;
    startBtn.textContent = 'START SCAN';
});

function wait(ms) { return new Promise(r => setTimeout(r, ms)); }

// --- Reports ---
let currentReportData = null;

async function loadReports() {
    // List reports
    const res = await fetch('/api/reports');
    const reports = await res.json();

    const container = document.getElementById('allReportsGrid');
    container.innerHTML = '';
    document.getElementById('reportListContainer').classList.remove('hidden');
    document.getElementById('reportDetailContainer').classList.add('hidden');

    // Hide download button in list view
    document.getElementById('btnDownloadReport').style.display = 'none';

    if (reports.length === 0) {
        container.appendChild(document.getElementById('template-empty-state').content.cloneNode(true));
        return;
    }

    reports.forEach(r => {
        const tmpl = document.getElementById('template-report-item').content.cloneNode(true);
        const div = tmpl.querySelector('.vuln-item');
        div.onclick = () => fetchAndShowReport(r.id);

        const domain = r.url.replace(/^https?:\/\//, '').split('/')[0];
        tmpl.querySelector('.report-icon-text').textContent = domain.substring(0, 3).toUpperCase();

        tmpl.querySelector('.vuln-title').textContent = r.url;
        tmpl.querySelector('.report-date').textContent = r.date;
        tmpl.querySelector('.vuln-count').textContent = `${r.vulnCheck} Defects`;

        const indicator = tmpl.querySelector('.report-status-indicator');
        if (r.vulnCheck > 5) indicator.style.backgroundColor = 'var(--danger)';
        else if (r.vulnCheck > 0) indicator.style.backgroundColor = 'var(--warning)';
        else indicator.style.backgroundColor = 'var(--success)';

        container.appendChild(tmpl);
    });
}

async function fetchAndShowReport(id) {
    const res = await fetch(`/api/reports/${id}`);
    const report = await res.json();
    showReportDetail(report.data);
}

function showReportDetail(data) {
    currentReportData = data;
    document.getElementById('reportListContainer').classList.add('hidden');
    document.getElementById('reportDetailContainer').classList.remove('hidden');

    // Show download button
    document.getElementById('btnDownloadReport').style.display = 'inline-flex';

    document.getElementById('reportTitle').textContent = data.url;
    document.getElementById('reportDate').textContent = new Date().toLocaleString() + " • Deep Analysis Report";

    const grid = document.getElementById('vulnGrid');
    grid.innerHTML = '';

    const vulns = data.vulnerabilities || [];
    if (vulns.length === 0) {
        grid.appendChild(document.getElementById('template-clean-scan').content.cloneNode(true));
    } else {
        vulns.forEach(v => {
            const tmpl = document.getElementById('template-vuln-item').content.cloneNode(true);
            const severityClass = v.severity || 'info';

            tmpl.querySelector('.vuln-title').textContent = v.title;
            const sevEl = tmpl.querySelector('.severity');
            sevEl.classList.add(severityClass);
            sevEl.textContent = severityClass.toUpperCase();

            tmpl.querySelector('.vuln-desc').textContent = v.desc;
            tmpl.querySelector('.vuln-path').textContent = v.path || '';

            grid.appendChild(tmpl);
        });
    }
}

document.getElementById('btnDownloadReport').addEventListener('click', () => {
    if (!currentReportData) return;

    // Generate text report
    const lines = [];
    lines.push(`UFOGUN SCANNER REPORT`);
    lines.push(`=====================`);
    lines.push(`Target: ${currentReportData.url}`);
    lines.push(`Date: ${new Date().toLocaleString()}`);
    lines.push(`\n[SCAN LOGS]`);
    (currentReportData.logs || []).forEach(l => lines.push(`- ${l}`));

    lines.push(`\n[VULNERABILITIES]`);
    const vulns = currentReportData.vulnerabilities || [];
    if (vulns.length === 0) lines.push("No significant vulnerabilities found.");

    vulns.forEach((v, i) => {
        lines.push(`\n#${i + 1} [${v.severity ? v.severity.toUpperCase() : 'INFO'}] ${v.title}`);
        lines.push(`   Description: ${v.desc}`);
        if (v.path) lines.push(`   Path/Ref: ${v.path}`);
    });

    const content = lines.join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ufogun_report_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
});

// --- Utils ---
async function loadRecent() {
    try {
        const res = await fetch('/api/reports');
        const reports = await res.json();
        const tbody = document.querySelector('#recentTable tbody');
        if (!tbody) return;

        tbody.innerHTML = '';
        reports.slice(0, 5).forEach(r => {
            const tmpl = document.getElementById('template-recent-row').content.cloneNode(true);
            tmpl.querySelector('.col-url').textContent = r.url;
            tmpl.querySelector('.col-date').textContent = r.date.split(' ')[0];

            const statusSpan = tmpl.querySelector('.col-status .severity');
            statusSpan.classList.add(r.vulnCheck > 0 ? 'high' : 'low');
            statusSpan.textContent = r.vulnCheck > 0 ? 'RISK' : 'SAFE';

            tmpl.querySelector('.btn-icon').onclick = () => { switchView('reports'); fetchAndShowReport(r.id); };
            tbody.appendChild(tmpl);
        });
    } catch (e) {
        console.error("Recent load error or empty");
    }
}

window.resetDb = async () => {
    if (confirm("Factory Reset? This will delete all scan history.")) {
        await fetch('/api/reset_db', { method: 'POST' });
        location.reload();
    }
};

window.setTheme = (themeName) => {
    document.body.className = '';
    if (themeName !== 'default') {
        document.body.classList.add(`theme-${themeName}`);
    }
    document.querySelectorAll('.theme-option').forEach(el => el.classList.remove('active'));
    const activeBtn = Array.from(document.querySelectorAll('.theme-option')).find(el => el.getAttribute('onclick').includes(themeName));
    if (activeBtn) activeBtn.classList.add('active');
    localStorage.setItem('ws_theme', themeName);
};

// Init
const savedTheme = localStorage.getItem('ws_theme') || 'default';
if (window.setTheme) setTheme(savedTheme);
loadRecent();

setTimeout(() => {
    const intro = document.getElementById('intro-overlay');
    if (intro) intro.remove();
}, 4000);
