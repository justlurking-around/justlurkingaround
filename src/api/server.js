'use strict';

/**
 * DAY 4 — REST API + Web Dashboard Server
 *
 * Express server exposing:
 *  GET  /api/stats              — scanner statistics
 *  GET  /api/findings           — paginated findings list
 *  GET  /api/findings/:id       — single finding detail
 *  GET  /api/repos              — scanned repos list
 *  POST /api/scan               — trigger on-demand scan
 *  GET  /api/live               — SSE stream for real-time updates
 *  GET  /health                 — health check
 *  GET  /                       — web dashboard (HTML)
 */

const express = require('express');
const path = require('path');
const { getDB } = require('../db');
const logger = require('../utils/logger');

class APIServer {
  constructor(port = 3000) {
    this.port = parseInt(process.env.API_PORT || port);
    this.app = express();
    this._sseClients = new Set();
    this._setupMiddleware();
    this._setupRoutes();
  }

  _setupMiddleware() {
    this.app.use(express.json());
    this.app.use((req, res, next) => {
      res.setHeader('X-Powered-By', 'ai-secret-scanner');
      res.setHeader('Access-Control-Allow-Origin', '*');
      next();
    });
  }

  _setupRoutes() {
    const app = this.app;

    // ── Health ──────────────────────────────────────────────────────────────
    app.get('/health', (req, res) => {
      // Try to return the self-heal report if available
      const healthFile = require('path').join(__dirname, '../../data/health.json');
      const fs = require('fs');
      if (fs.existsSync(healthFile)) {
        try {
          const data = JSON.parse(fs.readFileSync(healthFile, 'utf8'));
          return res.json(data);
        } catch {}
      }
      res.json({ status: 'ok', timestamp: new Date().toISOString() });
    });

    // ── Stats ───────────────────────────────────────────────────────────────
    app.get('/api/stats', async (req, res) => {
      try {
        const db = await getDB();
        const stats = await db.getStats();
        res.json({ success: true, data: stats });
      } catch (err) {
        res.status(500).json({ success: false, error: err.message });
      }
    });

    // ── Findings ────────────────────────────────────────────────────────────
    app.get('/api/findings', async (req, res) => {
      try {
        const db = await getDB();
        const limit  = Math.min(parseInt(req.query.limit  || '50'), 500);
        const offset = parseInt(req.query.offset || '0');
        const provider  = req.query.provider || null;
        const status    = req.query.status   || null;
        const repoName  = req.query.repo     || null;

        let findings = await db.getRecentFindings(limit + offset);
        // Apply filters (in-memory for JSONL backend)
        if (provider)  findings = findings.filter(f => f.provider === provider);
        if (status)    findings = findings.filter(f => f.validation_result === status.toUpperCase());
        if (repoName)  findings = findings.filter(f => f.repo_name?.includes(repoName));

        const total = findings.length;
        const page = findings.slice(offset, offset + limit);

        res.json({
          success: true,
          data: page,
          meta: { total, limit, offset }
        });
      } catch (err) {
        res.status(500).json({ success: false, error: err.message });
      }
    });

    // ── Repos ────────────────────────────────────────────────────────────────
    app.get('/api/repos', async (req, res) => {
      try {
        const db = await getDB();
        // Derive repo list from findings
        const findings = await db.getRecentFindings(1000);
        const repos = {};
        for (const f of findings) {
          const name = f.repo_name;
          if (!repos[name]) repos[name] = { name, findingCount: 0, validCount: 0 };
          repos[name].findingCount++;
          if (f.validation_result === 'VALID') repos[name].validCount++;
        }
        res.json({ success: true, data: Object.values(repos).slice(0, 200) });
      } catch (err) {
        res.status(500).json({ success: false, error: err.message });
      }
    });

    // ── On-demand scan ───────────────────────────────────────────────────────
    app.post('/api/scan', async (req, res) => {
      const { repoUrl } = req.body;
      if (!repoUrl) return res.status(400).json({ error: 'repoUrl required' });

      const repoName = repoUrl
        .replace(/https?:\/\/github\.com\//, '')
        .replace(/\.git$/, '').replace(/\/$/, '');

      if (!repoName.includes('/')) {
        return res.status(400).json({ error: 'Invalid GitHub repo URL' });
      }

      // Async — fire and forget, push updates via SSE
      res.json({ success: true, message: `Scan queued for ${repoName}`, repoName });

      // Trigger scan in background
      setImmediate(async () => {
        try {
          const ScannerEngine = require('../scanner/engine');
          const scanner = new ScannerEngine();
          const findings = await scanner.scanRepo({
            repoName, repoUrl, pushedAt: new Date().toISOString()
          });

          this._broadcast({ type: 'scan_complete', repoName, findingCount: findings.length });
          logger.info(`[API] On-demand scan: ${repoName} → ${findings.length} findings`);
        } catch (err) {
          this._broadcast({ type: 'scan_error', repoName, error: err.message });
        }
      });
    });

    // ── SSE live stream ──────────────────────────────────────────────────────
    app.get('/api/live', (req, res) => {
      res.setHeader('Content-Type',  'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection',    'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no');
      res.flushHeaders?.();

      res.write(`data: ${JSON.stringify({ type: 'connected', timestamp: new Date().toISOString() })}\n\n`);

      this._sseClients.add(res);
      logger.debug(`[SSE] Client connected (${this._sseClients.size} total)`);

      const heartbeat = setInterval(() => {
        res.write(`: heartbeat\n\n`);
      }, 30_000);

      req.on('close', () => {
        clearInterval(heartbeat);
        this._sseClients.delete(res);
        logger.debug(`[SSE] Client disconnected (${this._sseClients.size} remaining)`);
      });
    });

    // ── Web Dashboard ────────────────────────────────────────────────────────
    app.get('/', (req, res) => {
      res.setHeader('Content-Type', 'text/html');
      res.send(this._renderDashboard());
    });
  }

  /** Push event to all SSE clients */
  _broadcast(event) {
    const data = `data: ${JSON.stringify(event)}\n\n`;
    for (const client of this._sseClients) {
      try { client.write(data); } catch {}
    }
  }

  /** Notify worker to broadcast a new finding */
  pushFinding(finding) {
    this._broadcast({
      type: 'new_finding',
      timestamp: new Date().toISOString(),
      repoName: finding.repoName,
      provider: finding.provider,
      patternName: finding.patternName,
      filePath: finding.filePath,
      validationResult: finding.validationResult,
      entropy: finding.entropy
    });
  }

  start() {
    this.app.listen(this.port, '0.0.0.0', () => {
      logger.info(`[API] Dashboard running at http://localhost:${this.port}`);
    });
  }

  // ── HTML Dashboard ─────────────────────────────────────────────────────────

  _renderDashboard() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Secret Scanner — Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
    header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; display: flex; align-items: center; gap: 12px; }
    header h1 { font-size: 20px; font-weight: 700; color: #f0f6fc; }
    header .badge { background: #238636; color: #fff; font-size: 11px; padding: 2px 8px; border-radius: 12px; }
    .live-dot { width: 8px; height: 8px; border-radius: 50%; background: #3fb950; animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
    main { padding: 24px; max-width: 1400px; margin: 0 auto; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 28px; }
    .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
    .stat-card .label { font-size: 12px; color: #8b949e; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 8px; }
    .stat-card .value { font-size: 32px; font-weight: 700; color: #f0f6fc; }
    .stat-card.danger .value { color: #f85149; }
    .section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 24px; overflow: hidden; }
    .section-header { padding: 12px 16px; border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; }
    .section-header h2 { font-size: 14px; font-weight: 600; color: #f0f6fc; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { background: #0d1117; padding: 10px 12px; text-align: left; color: #8b949e; font-weight: 500; font-size: 12px; text-transform: uppercase; }
    td { padding: 10px 12px; border-top: 1px solid #21262d; }
    tr:hover td { background: #1c2128; }
    .badge-valid   { background: #3d1a1a; color: #f85149; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .badge-invalid { background: #1c262d; color: #8b949e; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
    .badge-skipped { background: #1c2028; color: #58a6ff; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
    .badge-error   { background: #2d2200; color: #d29922; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
    .scan-form { padding: 16px; display: flex; gap: 8px; }
    .scan-form input { flex: 1; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 8px 12px; color: #c9d1d9; font-size: 14px; outline: none; }
    .scan-form input:focus { border-color: #58a6ff; }
    .scan-form button { background: #238636; border: none; border-radius: 6px; padding: 8px 16px; color: #fff; font-size: 14px; cursor: pointer; font-weight: 600; }
    .scan-form button:hover { background: #2ea043; }
    #live-feed { padding: 0; max-height: 300px; overflow-y: auto; }
    .live-item { padding: 8px 16px; border-top: 1px solid #21262d; font-size: 12px; display: flex; gap: 8px; align-items: center; }
    .live-item .time { color: #8b949e; min-width: 80px; }
    .live-item.valid { background: #1a0e0e; }
    code { background: #0d1117; padding: 1px 6px; border-radius: 4px; font-family: monospace; font-size: 12px; }
    .empty { padding: 40px; text-align: center; color: #8b949e; }
  </style>
</head>
<body>
  <header>
    <div class="live-dot" id="conn-dot" style="background:#8b949e"></div>
    <h1>🔍 AI Secret Scanner</h1>
    <span class="badge">LIVE</span>
  </header>
  <main>
    <div class="stats" id="stats-grid">
      <div class="stat-card"><div class="label">Repositories</div><div class="value" id="s-repos">—</div></div>
      <div class="stat-card"><div class="label">Total Findings</div><div class="value" id="s-findings">—</div></div>
      <div class="stat-card danger"><div class="label">🚨 Live Secrets</div><div class="value" id="s-valid">—</div></div>
      <div class="stat-card"><div class="label">Queue Size</div><div class="value" id="s-queue">—</div></div>
      <div class="stat-card" id="health-card"><div class="label">System Health</div><div class="value" id="s-health" style="font-size:18px">—</div></div>
    </div>

    <div class="section">
      <div class="section-header"><h2>⚡ Scan Repository</h2></div>
      <div class="scan-form">
        <input type="text" id="scan-url" placeholder="https://github.com/owner/repo" />
        <button onclick="triggerScan()">Scan Now</button>
      </div>
    </div>

    <div class="section">
      <div class="section-header">
        <h2>📡 Live Feed</h2>
        <span id="live-status" style="font-size:12px;color:#8b949e">Connecting...</span>
      </div>
      <div id="live-feed"><div class="empty">Waiting for events...</div></div>
    </div>

    <div class="section">
      <div class="section-header">
        <h2>🔍 Recent Findings</h2>
        <div style="display:flex;gap:8px;font-size:12px">
          <select id="filter-status" onchange="loadFindings()" style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:4px 8px;border-radius:4px">
            <option value="">All Status</option>
            <option value="VALID">VALID (Live)</option>
            <option value="INVALID">INVALID</option>
            <option value="SKIPPED">SKIPPED</option>
          </select>
          <input type="text" id="filter-repo" placeholder="Filter by repo..." onkeyup="loadFindings()" style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:4px 8px;border-radius:4px;width:200px"/>
        </div>
      </div>
      <div id="findings-table"><div class="empty">Loading findings...</div></div>
    </div>
  </main>

  <script>
    // Load stats
    async function loadStats() {
      try {
        const r = await fetch('/api/stats');
        const { data } = await r.json();
        document.getElementById('s-repos').textContent    = data.repositories ?? '—';
        document.getElementById('s-findings').textContent  = data.findings ?? '—';
        document.getElementById('s-valid').textContent     = data.validSecrets ?? '—';
      } catch {}
    }

    // Load findings
    async function loadFindings() {
      const status = document.getElementById('filter-status').value;
      const repo   = document.getElementById('filter-repo').value;
      let url = '/api/findings?limit=50';
      if (status) url += '&status=' + status;
      if (repo)   url += '&repo=' + encodeURIComponent(repo);
      try {
        const r = await fetch(url);
        const { data, meta } = await r.json();
        renderFindings(data, meta);
      } catch (e) {
        document.getElementById('findings-table').innerHTML = '<div class="empty">Error loading findings</div>';
      }
    }

    function renderFindings(findings, meta) {
      if (!findings || findings.length === 0) {
        document.getElementById('findings-table').innerHTML = '<div class="empty">No findings yet — start a scan or wait for the real-time poller</div>';
        return;
      }
      const rows = findings.map(f => {
        const statusClass = {VALID:'valid',INVALID:'invalid',SKIPPED:'skipped',ERROR:'error'}[f.validation_result] || 'invalid';
        return \`<tr>
          <td><span class="badge-\${statusClass}">\${f.validation_result||'?'}</span></td>
          <td>\${f.provider||'?'}</td>
          <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${f.pattern_name||f.patternName||''}</td>
          <td><code>\${(f.repo_name||'').substring(0,35)}</code></td>
          <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><code>\${f.file_path||''}</code></td>
          <td>\${f.entropy||''}</td>
          <td style="color:#8b949e;font-size:11px">\${(f.detected_at||'').substring(0,16)}</td>
        </tr>\`;
      }).join('');
      document.getElementById('findings-table').innerHTML = \`
        <table>
          <thead><tr><th>Status</th><th>Provider</th><th>Pattern</th><th>Repo</th><th>File</th><th>Entropy</th><th>Detected</th></tr></thead>
          <tbody>\${rows}</tbody>
        </table>
      \`;
    }

    // SSE live feed
    function connectSSE() {
      const es = new EventSource('/api/live');
      const feed = document.getElementById('live-feed');
      const dot  = document.getElementById('conn-dot');
      const liveStatus = document.getElementById('live-status');

      es.onopen = () => {
        dot.style.background = '#3fb950';
        liveStatus.textContent = 'Connected';
      };
      es.onerror = () => {
        dot.style.background = '#f85149';
        liveStatus.textContent = 'Disconnected — reconnecting...';
        setTimeout(connectSSE, 5000);
        es.close();
      };
      es.onmessage = (e) => {
        try {
          const event = JSON.parse(e.data);
          if (event.type === 'connected') return;
          if (event.type === 'heartbeat') return;

          const isValid = event.validationResult === 'VALID';
          const item = document.createElement('div');
          item.className = 'live-item' + (isValid ? ' valid' : '');
          item.innerHTML = \`
            <span class="time">\${new Date().toTimeString().slice(0,8)}</span>
            <span class="badge-\${isValid?'valid':'skipped'}">\${event.validationResult||event.type}</span>
            <code>\${(event.repoName||'').substring(0,30)}</code>
            <span>\${event.patternName||event.type||''}</span>
          \`;
          if (feed.querySelector('.empty')) feed.innerHTML = '';
          feed.prepend(item);
          if (feed.children.length > 50) feed.lastChild.remove();

          loadStats();
          if (isValid) loadFindings();
        } catch {}
      };
    }

    // Trigger scan
    async function triggerScan() {
      const url = document.getElementById('scan-url').value.trim();
      if (!url) return;
      try {
        const r = await fetch('/api/scan', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ repoUrl: url })
        });
        const d = await r.json();
        alert(d.message || 'Scan queued');
      } catch (e) {
        alert('Scan failed: ' + e.message);
      }
    }

    // Load system health
    async function loadHealth() {
      try {
        const r = await fetch('/health');
        const d = await r.json();
        const el = document.getElementById('s-health');
        const card = document.getElementById('health-card');
        const colors = { healthy:'#3fb950', degraded:'#d29922', vulnerable:'#f85149', crashed:'#f85149' };
        el.textContent = (d.status || 'ok').toUpperCase();
        el.style.color = colors[d.status] || '#3fb950';
        if (d.vulnerabilities?.total > 0) {
          card.title = 'Vulns: crit=' + d.vulnerabilities.critical + ' high=' + d.vulnerabilities.high;
        }
      } catch {}
    }

    // Init
    loadStats();
    loadFindings();
    loadHealth();
    connectSSE();
    setInterval(loadStats, 30_000);
    setInterval(loadFindings, 60_000);
    setInterval(loadHealth, 5 * 60_000);
  </script>
</body>
</html>`;
  }
}

module.exports = APIServer;
