"""
dashboard.py - Flask-based web dashboard for PortIntel.

Provides a modern, responsive web UI to:
  • Initiate port scans via a form
  • View real-time scan progress
  • Browse scan history
  • Visualize results with charts

Run standalone:
    python -m port_scanner.dashboard
"""

import json
import os
import threading
import time
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, send_from_directory

from port_scanner.scanner import PortScanner, ScanResult
from port_scanner.utils import parse_targets, is_host_alive, guess_os, get_port_range
from port_scanner.reporter import save_json, save_txt
from port_scanner.logger import setup_logger

logger = setup_logger()

app = Flask(__name__)

# ── In-memory state ──────────────────────────────────────────────────
scan_history = []           # list of completed scan dicts
active_scan = {             # current scan progress
    "running": False,
    "target": "",
    "progress": 0,
    "total": 0,
    "status": "idle",
}
_scan_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════
#  HTML TEMPLATE  (single-file for portability)
# ═══════════════════════════════════════════════════════════════════════

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PortIntel — Dashboard</title>
    <meta name="description" content="PortIntel autonomous port scanner web dashboard">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        /* ── CSS Reset & Variables ─────────────────────────────────── */
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        :root {
            --bg-primary:    #0a0e1a;
            --bg-secondary:  #111827;
            --bg-card:       #1a1f35;
            --bg-card-hover: #222845;
            --bg-input:      #151b2e;
            --border:        #2a3350;
            --border-glow:   rgba(99, 102, 241, 0.4);
            --text-primary:  #e2e8f0;
            --text-secondary:#94a3b8;
            --text-muted:    #64748b;
            --accent:        #6366f1;
            --accent-hover:  #818cf8;
            --accent-glow:   rgba(99, 102, 241, 0.25);
            --success:       #22c55e;
            --success-bg:    rgba(34, 197, 94, 0.12);
            --danger:        #ef4444;
            --danger-bg:     rgba(239, 68, 68, 0.12);
            --warning:       #f59e0b;
            --warning-bg:    rgba(245, 158, 11, 0.12);
            --info:          #3b82f6;
            --info-bg:       rgba(59, 130, 246, 0.12);
            --gradient-1:    linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #a855f7 100%);
            --gradient-2:    linear-gradient(135deg, #0a0e1a 0%, #1a1f35 100%);
            --shadow-sm:     0 1px 3px rgba(0,0,0,0.3);
            --shadow-md:     0 4px 12px rgba(0,0,0,0.4);
            --shadow-lg:     0 8px 30px rgba(0,0,0,0.5);
            --shadow-glow:   0 0 25px var(--accent-glow);
            --radius:        12px;
            --radius-lg:     16px;
            --transition:    all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            --font-sans:     'Inter', -apple-system, sans-serif;
            --font-mono:     'JetBrains Mono', 'Fira Code', monospace;
        }

        html { scroll-behavior: smooth; }

        body {
            font-family: var(--font-sans);
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }

        /* ── Scrollbar ─────────────────────────────────────────────── */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg-secondary); }
        ::-webkit-scrollbar-thumb {
            background: var(--border);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover { background: var(--accent); }

        /* ── Background Pattern ────────────────────────────────────── */
        body::before {
            content: '';
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background:
                radial-gradient(ellipse at 20% 50%, rgba(99, 102, 241, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 20%, rgba(139, 92, 246, 0.06) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 80%, rgba(168, 85, 247, 0.04) 0%, transparent 50%);
            pointer-events: none;
            z-index: 0;
        }

        /* ── Layout ────────────────────────────────────────────────── */
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 24px;
            position: relative;
            z-index: 1;
        }

        /* ── Header ────────────────────────────────────────────────── */
        header {
            padding: 32px 0 24px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 32px;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .logo-icon {
            width: 48px; height: 48px;
            background: var(--gradient-1);
            border-radius: var(--radius);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            box-shadow: var(--shadow-glow);
        }

        .logo h1 {
            font-size: 28px;
            font-weight: 800;
            background: var(--gradient-1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.5px;
        }

        .logo p {
            font-size: 13px;
            color: var(--text-muted);
            font-weight: 400;
        }

        /* ── Cards ─────────────────────────────────────────────────── */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 24px;
            transition: var(--transition);
            box-shadow: var(--shadow-sm);
        }

        .card:hover {
            border-color: var(--border-glow);
            box-shadow: var(--shadow-glow);
        }

        .card-title {
            font-size: 16px;
            font-weight: 700;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            color: var(--text-primary);
        }

        .card-title .icon {
            width: 32px; height: 32px;
            background: var(--accent-glow);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
        }

        /* ── Form ──────────────────────────────────────────────────── */
        .scan-form {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .form-group.full-width {
            grid-column: 1 / -1;
        }

        .form-group label {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        input, select {
            font-family: var(--font-mono);
            font-size: 14px;
            padding: 12px 16px;
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            transition: var(--transition);
            outline: none;
        }

        input:focus, select:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }

        input::placeholder { color: var(--text-muted); }

        .btn {
            font-family: var(--font-sans);
            font-size: 14px;
            font-weight: 600;
            padding: 12px 28px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: var(--transition);
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .btn-primary {
            background: var(--gradient-1);
            color: white;
            box-shadow: var(--shadow-glow);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 0 35px var(--accent-glow);
        }

        .btn-primary:active { transform: translateY(0); }

        .btn-primary:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }

        .btn-secondary {
            background: var(--bg-input);
            color: var(--text-secondary);
            border: 1px solid var(--border);
        }

        .btn-secondary:hover {
            background: var(--bg-card-hover);
            color: var(--text-primary);
        }

        /* ── Stats Grid ────────────────────────────────────────────── */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px;
            text-align: center;
            transition: var(--transition);
        }

        .stat-card:hover {
            transform: translateY(-3px);
            box-shadow: var(--shadow-md);
        }

        .stat-value {
            font-size: 36px;
            font-weight: 800;
            font-family: var(--font-mono);
            line-height: 1.2;
        }

        .stat-value.open { color: var(--success); }
        .stat-value.closed { color: var(--danger); }
        .stat-value.filtered { color: var(--warning); }
        .stat-value.total { color: var(--info); }

        .stat-label {
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 4px;
        }

        /* ── Progress ──────────────────────────────────────────────── */
        .progress-container {
            margin: 20px 0;
            display: none;
        }

        .progress-container.active { display: block; }

        .progress-bar-bg {
            width: 100%;
            height: 8px;
            background: var(--bg-input);
            border-radius: 4px;
            overflow: hidden;
        }

        .progress-bar-fill {
            height: 100%;
            background: var(--gradient-1);
            border-radius: 4px;
            transition: width 0.5s ease;
            box-shadow: 0 0 12px var(--accent-glow);
        }

        .progress-text {
            display: flex;
            justify-content: space-between;
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 8px;
            font-family: var(--font-mono);
        }

        /* ── Results Table ─────────────────────────────────────────── */
        .results-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }

        .results-table th {
            text-align: left;
            padding: 12px 16px;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            background: var(--bg-input);
            border-bottom: 1px solid var(--border);
        }

        .results-table th:first-child { border-radius: 8px 0 0 0; }
        .results-table th:last-child  { border-radius: 0 8px 0 0; }

        .results-table td {
            padding: 12px 16px;
            border-bottom: 1px solid rgba(42, 51, 80, 0.5);
            font-family: var(--font-mono);
            font-size: 13px;
        }

        .results-table tr:hover td {
            background: var(--bg-card-hover);
        }

        .results-table tr:last-child td { border-bottom: none; }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge-open     { background: var(--success-bg); color: var(--success); }
        .badge-closed   { background: var(--danger-bg);  color: var(--danger);  }
        .badge-filtered { background: var(--warning-bg); color: var(--warning); }

        /* ── Charts ────────────────────────────────────────────────── */
        .chart-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-top: 24px;
        }

        .chart-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 24px;
        }

        .donut-chart {
            width: 180px;
            height: 180px;
            margin: 20px auto;
            position: relative;
        }

        .donut-chart canvas { width: 100% !important; height: 100% !important; }

        .bar-chart { height: 250px; position: relative; }

        /* ── Scan History ──────────────────────────────────────────── */
        .history-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 14px 16px;
            border-bottom: 1px solid rgba(42, 51, 80, 0.4);
            transition: var(--transition);
        }

        .history-item:hover { background: var(--bg-card-hover); }
        .history-item:last-child { border-bottom: none; }

        .history-target {
            font-family: var(--font-mono);
            font-weight: 600;
            color: var(--accent-hover);
        }

        .history-meta {
            font-size: 12px;
            color: var(--text-muted);
        }

        /* ── Warning Banner ────────────────────────────────────────── */
        .warning-banner {
            background: rgba(245, 158, 11, 0.08);
            border: 1px solid rgba(245, 158, 11, 0.3);
            border-radius: var(--radius);
            padding: 14px 20px;
            margin-bottom: 24px;
            font-size: 13px;
            color: var(--warning);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        /* ── Layout Grid ───────────────────────────────────────────── */
        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-top: 24px;
        }

        /* ── Status indicator ──────────────────────────────────────── */
        .status-dot {
            width: 8px; height: 8px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 6px;
        }

        .status-dot.idle      { background: var(--text-muted); }
        .status-dot.running    { background: var(--success); animation: pulse 1.5s infinite; }
        .status-dot.completed  { background: var(--info); }
        .status-dot.error      { background: var(--danger); }

        @keyframes pulse {
            0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.4); }
            50%      { opacity: 0.7; box-shadow: 0 0 0 6px rgba(34, 197, 94, 0); }
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to   { opacity: 1; transform: translateY(0); }
        }

        .fade-in { animation: fadeIn 0.4s ease-out; }

        /* ── Responsive ────────────────────────────────────────────── */
        @media (max-width: 768px) {
            .scan-form          { grid-template-columns: 1fr; }
            .stats-grid         { grid-template-columns: repeat(2, 1fr); }
            .chart-container    { grid-template-columns: 1fr; }
            .grid-2             { grid-template-columns: 1fr; }
            .logo h1            { font-size: 22px; }
        }

        /* ── Toast Notification ────────────────────────────────────── */
        .toast {
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: var(--bg-card);
            border: 1px solid var(--accent);
            border-radius: var(--radius);
            padding: 16px 24px;
            box-shadow: var(--shadow-lg);
            z-index: 1000;
            animation: slideUp 0.3s ease-out;
            display: none;
        }

        .toast.show { display: flex; align-items: center; gap: 10px; }

        @keyframes slideUp {
            from { transform: translateY(20px); opacity: 0; }
            to   { transform: translateY(0); opacity: 1; }
        }

        /* ── Footer ────────────────────────────────────────────────── */
        footer {
            text-align: center;
            padding: 32px 0;
            color: var(--text-muted);
            font-size: 13px;
            border-top: 1px solid var(--border);
            margin-top: 48px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <div class="logo">
                <div class="logo-icon">🔍</div>
                <div>
                    <h1>PortIntel</h1>
                    <p>Autonomous Port Scanner & Network Intelligence Dashboard</p>
                </div>
            </div>
        </header>

        <!-- Warning -->
        <div class="warning-banner">
            <span>⚠️</span>
            <span><strong>Authorized Use Only</strong> — Only scan systems you own or have explicit permission to test.</span>
        </div>

        <!-- Stats -->
        <div class="stats-grid" id="statsGrid">
            <div class="stat-card">
                <div class="stat-value total" id="statTotal">0</div>
                <div class="stat-label">Ports Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value open" id="statOpen">0</div>
                <div class="stat-label">Open</div>
            </div>
            <div class="stat-card">
                <div class="stat-value closed" id="statClosed">0</div>
                <div class="stat-label">Closed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value filtered" id="statFiltered">0</div>
                <div class="stat-label">Filtered</div>
            </div>
        </div>

        <!-- Scan Form -->
        <div class="card fade-in" id="scanFormCard">
            <div class="card-title">
                <div class="icon">🎯</div>
                New Scan
            </div>
            <form id="scanForm" class="scan-form" onsubmit="startScan(event)">
                <div class="form-group">
                    <label for="target">Target</label>
                    <input type="text" id="target" name="target"
                           placeholder="e.g. 192.168.1.1 or example.com"
                           required>
                </div>
                <div class="form-group">
                    <label for="ports">Ports</label>
                    <input type="text" id="ports" name="ports"
                           placeholder="common, all, 1-1024, 80,443"
                           value="common">
                </div>
                <div class="form-group">
                    <label for="threads">Threads</label>
                    <input type="number" id="threads" name="threads"
                           value="100" min="10" max="500">
                </div>
                <div class="form-group">
                    <label for="timeout">Timeout (s)</label>
                    <input type="number" id="timeout" name="timeout"
                           value="1.5" step="0.1" min="0.5" max="10">
                </div>
                <div class="form-group full-width" style="flex-direction:row; gap:12px; align-items:end;">
                    <button type="submit" class="btn btn-primary" id="scanBtn">
                        🚀 Start Scan
                    </button>
                    <button type="button" class="btn btn-secondary" onclick="stopScan()">
                        ⏹ Stop
                    </button>
                    <span id="scanStatus" style="font-size:13px;color:var(--text-muted);margin-left:auto;">
                        <span class="status-dot idle"></span> Idle
                    </span>
                </div>
            </form>
        </div>

        <!-- Progress -->
        <div class="progress-container" id="progressContainer">
            <div class="progress-bar-bg">
                <div class="progress-bar-fill" id="progressBar" style="width: 0%"></div>
            </div>
            <div class="progress-text">
                <span id="progressText">0 / 0 ports</span>
                <span id="progressPct">0%</span>
            </div>
        </div>

        <!-- Results -->
        <div class="grid-2" id="resultsSection" style="display:none;">
            <!-- Port Table -->
            <div class="card fade-in" style="grid-column: 1 / -1;">
                <div class="card-title">
                    <div class="icon">📊</div>
                    Scan Results
                    <span id="resultTarget" style="font-family:var(--font-mono);color:var(--accent-hover);margin-left:auto;font-size:14px;"></span>
                </div>
                <div style="overflow-x:auto;">
                    <table class="results-table" id="resultsTable">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>State</th>
                                <th>Service</th>
                                <th>Version</th>
                                <th>Banner</th>
                                <th>Response</th>
                            </tr>
                        </thead>
                        <tbody id="resultsBody"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Charts + History -->
        <div class="chart-container" id="chartsSection" style="display:none;">
            <div class="chart-card fade-in">
                <div class="card-title">
                    <div class="icon">🍩</div>
                    Port State Distribution
                </div>
                <div class="donut-chart">
                    <canvas id="donutChart"></canvas>
                </div>
            </div>
            <div class="chart-card fade-in">
                <div class="card-title">
                    <div class="icon">📜</div>
                    Scan History
                </div>
                <div id="historyList">
                    <div style="text-align:center;padding:40px;color:var(--text-muted);">
                        No scans yet
                    </div>
                </div>
            </div>
        </div>

        <footer>
            PortIntel v1.0.0 — Autonomous Port Scanner &amp; Network Intelligence Tool<br>
            For authorized use only. Use responsibly.
        </footer>
    </div>

    <!-- Toast -->
    <div class="toast" id="toast">
        <span id="toastIcon">✅</span>
        <span id="toastMsg"></span>
    </div>

    <!-- Chart.js from CDN -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>

    <script>
        // ── State ─────────────────────────────────────────────────
        let pollInterval = null;
        let donutChart = null;

        // ── Start Scan ────────────────────────────────────────────
        async function startScan(e) {
            e.preventDefault();
            const data = {
                target:  document.getElementById('target').value,
                ports:   document.getElementById('ports').value,
                threads: parseInt(document.getElementById('threads').value),
                timeout: parseFloat(document.getElementById('timeout').value),
            };

            document.getElementById('scanBtn').disabled = true;
            updateStatus('running', 'Scanning…');
            document.getElementById('progressContainer').classList.add('active');
            document.getElementById('resultsSection').style.display = 'none';
            document.getElementById('chartsSection').style.display  = 'none';

            try {
                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data),
                });
                const json = await res.json();
                if (json.error) {
                    showToast('❌', json.error);
                    updateStatus('error', 'Error');
                    document.getElementById('scanBtn').disabled = false;
                    return;
                }
                // Start polling
                pollInterval = setInterval(pollProgress, 800);
            } catch (err) {
                showToast('❌', 'Failed to start scan');
                updateStatus('error', 'Error');
                document.getElementById('scanBtn').disabled = false;
            }
        }

        // ── Poll Progress ─────────────────────────────────────────
        async function pollProgress() {
            try {
                const res  = await fetch('/api/progress');
                const data = await res.json();

                const pct = data.total > 0 ? (data.progress / data.total * 100) : 0;
                document.getElementById('progressBar').style.width = pct + '%';
                document.getElementById('progressText').textContent =
                    data.progress + ' / ' + data.total + ' ports';
                document.getElementById('progressPct').textContent = pct.toFixed(1) + '%';

                if (!data.running && data.status !== 'idle') {
                    clearInterval(pollInterval);
                    pollInterval = null;
                    document.getElementById('scanBtn').disabled = false;
                    updateStatus('completed', 'Completed');
                    loadResults();
                }
            } catch (err) {
                // ignore transient errors
            }
        }

        // ── Stop Scan ─────────────────────────────────────────────
        async function stopScan() {
            await fetch('/api/stop', { method: 'POST' });
            if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
            document.getElementById('scanBtn').disabled = false;
            updateStatus('idle', 'Stopped');
            showToast('⏹', 'Scan stopped');
        }

        // ── Load Results ──────────────────────────────────────────
        async function loadResults() {
            const res  = await fetch('/api/results');
            const data = await res.json();
            if (!data.scan_info) return;

            const info = data.scan_info;
            document.getElementById('statTotal').textContent   = info.total_scanned;
            document.getElementById('statOpen').textContent     = info.open_ports;
            document.getElementById('statClosed').textContent   = info.closed_ports;
            document.getElementById('statFiltered').textContent = info.filtered_ports;
            document.getElementById('resultTarget').textContent = info.ip;

            // Table
            const tbody = document.getElementById('resultsBody');
            tbody.innerHTML = '';
            (data.ports || []).forEach(p => {
                const tr = document.createElement('tr');
                const badgeClass = 'badge-' + p.state;
                const banner = (p.banner || '').replace(/</g, '&lt;').substring(0, 60);
                tr.innerHTML = `
                    <td>${p.port}/tcp</td>
                    <td><span class="badge ${badgeClass}">${p.state}</span></td>
                    <td>${p.service || '—'}</td>
                    <td>${p.version || '—'}</td>
                    <td style="color:var(--text-muted);font-size:12px;">${banner || '—'}</td>
                    <td>${p.response_time ? p.response_time.toFixed(3) + 's' : '—'}</td>
                `;
                tbody.appendChild(tr);
            });

            document.getElementById('resultsSection').style.display = 'grid';
            document.getElementById('chartsSection').style.display  = 'grid';

            // Donut
            renderDonut(info.open_ports, info.closed_ports, info.filtered_ports);

            // History
            loadHistory();

            showToast('✅', `Scan complete: ${info.open_ports} open ports found`);
        }

        // ── Donut Chart ───────────────────────────────────────────
        function renderDonut(open, closed, filtered) {
            const ctx = document.getElementById('donutChart').getContext('2d');
            if (donutChart) donutChart.destroy();
            donutChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Open', 'Closed', 'Filtered'],
                    datasets: [{
                        data: [open, closed, filtered],
                        backgroundColor: ['#22c55e', '#ef4444', '#f59e0b'],
                        borderColor: '#1a1f35',
                        borderWidth: 3,
                    }]
                },
                options: {
                    responsive: true,
                    cutout: '65%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#94a3b8', font: { family: 'Inter', size: 12 }, padding: 16 }
                        }
                    }
                }
            });
        }

        // ── History ───────────────────────────────────────────────
        async function loadHistory() {
            const res  = await fetch('/api/history');
            const data = await res.json();
            const el   = document.getElementById('historyList');
            if (!data.length) return;
            el.innerHTML = '';
            data.forEach(h => {
                const div = document.createElement('div');
                div.className = 'history-item';
                div.innerHTML = `
                    <div>
                        <div class="history-target">${h.target}</div>
                        <div class="history-meta">${h.open_ports} open · ${h.total_scanned} scanned · ${h.duration}s</div>
                    </div>
                    <div class="history-meta">${h.time}</div>
                `;
                el.appendChild(div);
            });
        }

        // ── Helpers ───────────────────────────────────────────────
        function updateStatus(state, text) {
            const el = document.getElementById('scanStatus');
            el.innerHTML = `<span class="status-dot ${state}"></span> ${text}`;
        }

        function showToast(icon, msg) {
            const t = document.getElementById('toast');
            document.getElementById('toastIcon').textContent = icon;
            document.getElementById('toastMsg').textContent  = msg;
            t.classList.add('show');
            setTimeout(() => t.classList.remove('show'), 3500);
        }
    </script>
</body>
</html>
"""


# ═══════════════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    """Serve the dashboard SPA."""
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Start a new scan in a background thread."""
    global active_scan

    with _scan_lock:
        if active_scan["running"]:
            return jsonify({"error": "A scan is already running."}), 409

    data = request.get_json(force=True)
    target = data.get("target", "").strip()
    port_spec = data.get("ports", "common")
    threads = int(data.get("threads", 100))
    timeout = float(data.get("timeout", 1.5))

    # Validate
    try:
        targets = parse_targets(target)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    try:
        ports = get_port_range(port_spec)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if not targets:
        return jsonify({"error": "No valid targets."}), 400

    ip = targets[0]  # dashboard scans one host at a time

    with _scan_lock:
        active_scan = {
            "running": True,
            "target": ip,
            "progress": 0,
            "total": len(ports),
            "status": "running",
        }

    def _run():
        global active_scan
        try:
            alive, ttl = is_host_alive(ip, timeout=timeout)
            if not alive:
                with _scan_lock:
                    active_scan["status"] = "host_down"
                    active_scan["running"] = False
                return

            os_guess = guess_os(ttl)

            def _progress(current, total):
                with _scan_lock:
                    active_scan["progress"] = current
                    active_scan["total"] = total

            scanner = PortScanner(
                target_ip=ip,
                ports=ports,
                timeout=timeout,
                threads=threads,
                autonomous=True,
                progress_callback=_progress,
            )
            result = scanner.scan()
            result.os_guess = os_guess
            result.ttl = ttl

            # Save to history
            scan_entry = {
                "scan_info": {
                    "target": result.target,
                    "ip": result.ip,
                    "os_guess": result.os_guess,
                    "ttl": result.ttl,
                    "scan_time": datetime.fromtimestamp(result.start_time).isoformat(),
                    "duration_seconds": round(result.duration, 2),
                    "total_scanned": result.total_scanned,
                    "open_ports": result.open_ports,
                    "closed_ports": result.closed_ports,
                    "filtered_ports": result.filtered_ports,
                },
                "ports": [
                    {
                        "port": p.port,
                        "state": p.state,
                        "service": p.service,
                        "version": p.version,
                        "banner": p.banner,
                        "response_time": p.response_time,
                    }
                    for p in result.ports
                    if p.state in ("open", "filtered")
                ],
            }
            scan_history.insert(0, scan_entry)

            with _scan_lock:
                active_scan["status"] = "completed"
                active_scan["running"] = False

        except Exception as exc:
            logger.error(f"Dashboard scan error: {exc}")
            with _scan_lock:
                active_scan["status"] = "error"
                active_scan["running"] = False

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return jsonify({"message": "Scan started", "target": ip, "ports": len(ports)})


@app.route("/api/progress")
def api_progress():
    """Return current scan progress."""
    with _scan_lock:
        return jsonify(active_scan)


@app.route("/api/stop", methods=["POST"])
def api_stop():
    """Stop the current scan."""
    with _scan_lock:
        active_scan["running"] = False
        active_scan["status"] = "stopped"
    return jsonify({"message": "Stop signal sent"})


@app.route("/api/results")
def api_results():
    """Return the most recent scan result."""
    if scan_history:
        return jsonify(scan_history[0])
    return jsonify({})


@app.route("/api/history")
def api_history():
    """Return summarised scan history."""
    items = []
    for entry in scan_history[:20]:
        info = entry.get("scan_info", {})
        items.append({
            "target": info.get("ip", "?"),
            "open_ports": info.get("open_ports", 0),
            "total_scanned": info.get("total_scanned", 0),
            "duration": info.get("duration_seconds", 0),
            "time": info.get("scan_time", ""),
        })
    return jsonify(items)


# ═══════════════════════════════════════════════════════════════════════
#  STANDALONE RUN
# ═══════════════════════════════════════════════════════════════════════

def run_dashboard(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    """Launch the Flask dashboard server."""
    print(f"\n  🌐  PortIntel Dashboard running at http://{host}:{port}\n")
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    run_dashboard(debug=True)
