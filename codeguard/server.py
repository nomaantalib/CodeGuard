"""HTTP API + tiny dashboard (stdlib only). Run: python -m codeguard serve

POST /api/scan            body = .zip, Authorization: Bearer <key>   -> 202 {id}
GET  /api/scans/<id>      status + summary
GET  /api/scans/<id>/report.(html|md|json|patch)
GET  /api/usage
POST /admin/keys          X-Admin-Token, {"email","plan"}
POST /webhooks/stripe     Stripe-Signature verified
"""
from __future__ import annotations

import hmac
import io
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .billing import PLANS, apply_event, quota_exceeded, verify_stripe_signature
from .config import load_config
from .pipeline import review
from .report import write_reports
from .store import Store


class Settings:
    def __init__(self):
        e = os.environ.get
        self.data_dir = Path(e("CODEGUARD_DATA", "./codeguard-data")).resolve()
        self.admin_token = e("CODEGUARD_ADMIN_TOKEN", "")
        self.stripe_secret = e("STRIPE_WEBHOOK_SECRET", "")
        self.sandbox = e("CODEGUARD_SANDBOX", "docker")  # docker | none
        self.allow_unsafe_local = e("CODEGUARD_ALLOW_UNSAFE_LOCAL") == "1"
        self.docker_image = e("CODEGUARD_DOCKER_IMAGE", "python:3.12-slim")
        self.workers = int(e("CODEGUARD_WORKERS", "2"))


def safe_extract(data: bytes, dest: Path, max_files: int = 5000, max_bytes: int = 200 * 1024 * 1024) -> Path:
    """Extract an untrusted zip: no path traversal, no symlinks, bounded size and file count."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    base = dest.resolve()
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if len(infos) > max_files:
            raise ValueError("archive has too many files")
        for i in infos:
            target = (base / i.filename).resolve()
            if target != base and base not in target.parents:
                raise ValueError("unsafe path in archive")
            if (i.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # skip symlinks
            if i.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(i) as src, open(target, "wb") as out:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("archive too large when extracted")
                    out.write(chunk)
    entries = [p for p in base.iterdir() if p.name != "__MACOSX"]
    return entries[0] if len(entries) == 1 and entries[0].is_dir() else base


def run_job(store: Store, settings: Settings, scan_id: str, account: dict, data: bytes, want_fix: bool, want_llm: bool):
    plan = PLANS[account["plan"]]
    tmp = Path(tempfile.mkdtemp(prefix="cg-job-"))
    try:
        store.update_scan(scan_id, status="running")
        root = safe_extract(data, tmp / "src")
        docker_ok = shutil.which("docker") is not None
        run_tests = (settings.sandbox == "docker" and docker_ok) or settings.allow_unsafe_local
        # Server-side overrides always win over a customer-supplied codeguard.toml.
        cfg = load_config(root, {
            "sandbox": "docker" if (settings.sandbox == "docker" and docker_ok) else "none",
            "run_tests": run_tests, "use_llm": bool(want_llm and plan["llm"]),
            "docker_network": "none", "docker_image": settings.docker_image, "test_timeout": 300})
        r = review(root, cfg, fix=bool(want_fix and plan["fix"]), apply=False)
        if not run_tests:
            r.notes.append("Tests were not executed: no sandbox available on this server (customer code is never run unsandboxed).")
        if want_fix and not plan["fix"]:
            r.notes.append("Auto-fix requires the Pro plan.")
        out = settings.data_dir / "scans" / scan_id
        write_reports(r, out)
        summary = {"before": r.score_before, "after": r.score_after, "fixes": len(r.fixes),
                   "accepted_fixes": sum(f.status == "accepted" for f in r.fixes), "notes": r.notes}
        store.update_scan(scan_id, status="done", finished=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                          score=r.score_after["overall"], summary=json.dumps(summary))
    except Exception as e:  # never leak internals to the customer
        print(f"[codeguard] job {scan_id} failed: {e!r}", file=sys.stderr)
        store.update_scan(scan_id, status="error", error=str(e)[:300])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


DASHBOARD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CodeGuard v2 - AI Code Review & Audit</title>
<style>
:root{--bg:#0f172a;--surface:#1e293b;--border:#334155;--text:#f8fafc;--muted:#94a3b8;--primary:#3b82f6;--primary-hover:#2563eb;--danger:#ef4444;--warning:#f59e0b;--success:#10b981;--font:ui-sans-serif,system-ui,-apple-system,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);line-height:1.5;padding:24px}
.container{max-width:1080px;margin:0 auto}
header{display:flex;justify-content:space-between;align-items:center;padding-bottom:20px;border-bottom:1px solid var(--border);margin-bottom:24px}
.brand{display:flex;align-items:center;gap:12px;font-size:22px;font-weight:700}
.brand span{background:linear-gradient(135deg,#60a5fa,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.badge{padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600;background:var(--border);color:var(--text)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px}
.dropzone{border:2px dashed var(--border);border-radius:12px;padding:36px;text-align:center;cursor:pointer;transition:all .2s;background:#0f172a66}
.dropzone:hover,.dropzone.dragover{border-color:var(--primary);background:#3b82f611}
.dropzone h3{margin-bottom:8px;font-size:18px}
.dropzone p{color:var(--muted);font-size:14px;margin-bottom:16px}
.btn{background:var(--primary);color:#fff;border:none;padding:10px 20px;border-radius:8px;font-weight:600;font-size:14px;cursor:pointer;display:inline-flex;align-items:center;gap:8px;transition:background .2s}
.btn:hover{background:var(--primary-hover)}
.btn-outline{background:transparent;border:1px solid var(--border);color:var(--text)}
.btn-outline:hover{background:var(--border)}
.controls{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin:20px 0}
.control-item{display:flex;flex-direction:column;gap:6px}
.control-item label{font-size:13px;color:var(--muted);font-weight:500}
input[type="text"],input[type="password"],select{background:#0f172a;border:1px solid var(--border);color:var(--text);padding:10px 12px;border-radius:8px;font-size:14px;outline:none}
input:focus,select:focus{border-color:var(--primary)}
.checkbox-label{display:flex;align-items:center;gap:8px;cursor:pointer;font-size:14px;margin-top:22px}
.progress-container{background:#0f172a;border:1px solid var(--border);border-radius:999px;height:14px;overflow:hidden;margin:16px 0 10px}
.progress-bar{background:linear-gradient(90deg,#3b82f6,#8b5cf6);height:100%;width:0%;transition:width 0.3s ease}
.progress-meta{display:flex;justify-content:space-between;align-items:center;font-size:14px}
.stepper{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0 10px;padding:16px;background:#0f172a88;border-radius:8px}
.step{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted)}
.step.active{color:var(--primary);font-weight:600}
.step.done{color:var(--success)}
.scorecard{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin:20px 0}
.score-box{background:#0f172a;border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center}
.score-val{font-size:32px;font-weight:800;margin:6px 0}
.score-band{display:inline-block;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700}
.band-Good{background:#10b98133;color:#10b981}
.band-NeedsWork{background:#f59e0b33;color:#f59e0b}
.band-CRITICAL{background:#ef444433;color:#ef4444}
.findings-list{display:flex;flex-direction:column;gap:12px;margin-top:16px}
.finding-item{background:#0f172a;border:1px solid var(--border);border-radius:8px;padding:16px}
.finding-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.sev-critical{color:#ef4444;font-weight:700}
.sev-high{color:#f97316;font-weight:700}
.sev-medium{color:#f59e0b;font-weight:600}
.sev-low{color:#3b82f6}
.evidence-quote{background:#1e293b;border-left:3px solid var(--primary);padding:8px 12px;margin:8px 0;font-family:monospace;font-size:13px;white-space:pre-wrap;border-radius:0 6px 6px 0}
.actions{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap}
pre{background:#0f172a;padding:12px;border-radius:8px;font-size:13px;overflow-x:auto}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      <span>CodeGuard v2</span>
      <span class="badge">Review & Reasoning Layer</span>
    </div>
    <div id="statusTag" class="badge">Ready</div>
  </header>

  <div class="card">
    <div class="dropzone" id="dropzone">
      <h3>Drop your project ZIP here</h3>
      <p>Or click to browse and select your project archive (.zip)</p>
      <input type="file" id="fileInput" accept=".zip" style="display:none">
      <button class="btn" onclick="document.getElementById('fileInput').click()">Select Project ZIP</button>
      <div id="selectedName" style="margin-top:12px;font-weight:600;color:var(--primary)"></div>
    </div>

    <div class="controls">
      <div class="control-item">
        <label>API Key (Auto-configured for local mode)</label>
        <input type="password" id="apiKey" placeholder="Auto-configured local key">
      </div>
      <div class="control-item">
        <label>Model Preset</label>
        <select id="modelPreset">
          <option value="ollama">Ollama Local (Auto-detect Qwen)</option>
          <option value="deepseek">DeepSeek (deepseek-coder)</option>
          <option value="qwen">Qwen / DashScope</option>
          <option value="glm">Zhipu GLM-4</option>
          <option value="kimi">Moonshot Kimi</option>
          <option value="openrouter">OpenRouter</option>
        </select>
      </div>
      <div class="control-item">
        <label class="checkbox-label">
          <input type="checkbox" id="fixCheck" checked>
          <span>P5: Verified Fix & Revert Loop</span>
        </label>
      </div>
      <div class="control-item">
        <label class="checkbox-label">
          <input type="checkbox" id="llmCheck" checked>
          <span>P1-P3: Multi-Pass AI Reasoning</span>
        </label>
      </div>
    </div>

    <button id="scanBtn" class="btn" style="width:100%;justify-content:center;padding:14px;font-size:16px">
      Run Audit
    </button>
  </div>

  <div id="progressCard" class="card" style="display:none">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <h3>Audit Execution Progress</h3>
      <span id="progressPercent" style="font-size:18px;font-weight:700;color:var(--primary)">0%</span>
    </div>

    <div class="progress-container">
      <div id="progressBar" class="progress-bar"></div>
    </div>

    <div class="progress-meta">
      <span id="statusLog" style="color:var(--muted)">Please wait while loading...</span>
      <span style="color:var(--muted);font-size:12px">Please wait while loading...</span>
    </div>

    <div class="stepper">
      <div id="step-p0" class="step"><span>[ ]</span> P0: Repo Plan</div>
      <div id="step-tests" class="step"><span>[ ]</span> Baseline Tests</div>
      <div id="step-p1" class="step"><span>[ ]</span> P1: Line Audit</div>
      <div id="step-ground" class="step"><span>[ ]</span> Grounding Gate</div>
      <div id="step-p2" class="step"><span>[ ]</span> P2: Skeptic Check</div>
      <div id="step-p5" class="step"><span>[ ]</span> P5: Fix QC</div>
      <div id="step-done" class="step"><span>[ ]</span> Scorecard & Report</div>
    </div>
  </div>

  <div id="resultsCard" class="card" style="display:none">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <h2>Audit Findings & Scorecard</h2>
      <div id="bandTag" class="score-band">Good</div>
    </div>

    <div class="scorecard">
      <div class="score-box">
        <div style="font-size:13px;color:var(--muted)">Composite Score</div>
        <div id="overallScore" class="score-val">--</div>
        <div id="overallGrade" class="badge">--</div>
      </div>
      <div class="score-box">
        <div style="font-size:13px;color:var(--muted)">Deterministic (30%)</div>
        <div id="detScore" class="score-val">--</div>
      </div>
      <div class="score-box">
        <div style="font-size:13px;color:var(--muted)">LLM Reasoning (70%)</div>
        <div id="llmScore" class="score-val">--</div>
      </div>
      <div class="score-box">
        <div style="font-size:13px;color:var(--muted)">Total Findings</div>
        <div id="totalFindings" class="score-val">--</div>
      </div>
    </div>

    <div class="actions">
      <button class="btn btn-outline" id="dlPatch">Download Patch (.patch)</button>
      <button class="btn btn-outline" id="dlMd">Download Markdown (.md)</button>
      <button class="btn btn-outline" id="dlHtml">Open HTML Report</button>
      <button class="btn btn-outline" id="dlJson">Export JSON</button>
    </div>

    <h3 style="margin-top:24px">Verified Findings</h3>
    <div id="findingsContainer" class="findings-list"></div>
  </div>
</div>

<script>
const $=id=>document.getElementById(id);
let activeFile=null;
let currentScanId=null;
const LOCAL_KEY = "__DEFAULT_KEY__";

const params = new URLSearchParams(window.location.search);
$('apiKey').value = params.get('key') || LOCAL_KEY;

$('dropzone').ondragover=e=>{e.preventDefault();$('dropzone').classList.add('dragover')};
$('dropzone').ondragleave=()=>$('dropzone').classList.remove('dragover');
$('dropzone').ondrop=e=>{
  e.preventDefault();
  $('dropzone').classList.remove('dragover');
  if(e.dataTransfer.files.length){
    activeFile=e.dataTransfer.files[0];
    $('selectedName').textContent='Selected: '+activeFile.name;
  }
};
$('fileInput').onchange=e=>{
  if(e.target.files.length){
    activeFile=e.target.files[0];
    $('selectedName').textContent='Selected: '+activeFile.name;
  }
};

const getKey = () => $('apiKey').value.trim() || LOCAL_KEY;
const H = () => ({ Authorization: 'Bearer ' + getKey() });

function updateProgress(pct, msg) {
  $('progressBar').style.width = pct + '%';
  $('progressPercent').textContent = pct + '%';
  $('statusLog').textContent = msg;
}

$('scanBtn').onclick=()=>{
  if(!activeFile){alert('Please select a project .zip first.');return}
  $('progressCard').style.display='block';
  $('resultsCard').style.display='none';
  $('statusTag').textContent='Scanning...';
  $('step-p0').className='step active';
  updateProgress(5, 'Uploading project archive... Please wait while loading...');

  const fix=$('fixCheck').checked?1:0;
  const llm=$('llmCheck').checked?1:0;

  const xhr = new XMLHttpRequest();
  xhr.open('POST', `/api/scan?fix=${fix}&llm=${llm}`);
  xhr.setRequestHeader('Authorization', 'Bearer ' + getKey());

  xhr.upload.onprogress = (e) => {
    if (e.lengthComputable) {
      const uploadPct = Math.round((e.loaded / e.total) * 30);
      updateProgress(uploadPct, `Uploading project archive (${Math.round((e.loaded/e.total)*100)}%)... Please wait while loading...`);
    }
  };

  let pollTimer = null;
  function schedulePoll(fn, delay) {
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = setTimeout(fn, delay);
  }

  xhr.onload = async () => {
    if (xhr.status >= 200 && xhr.status < 300) {
      try {
        const j = JSON.parse(xhr.responseText);
        currentScanId = j.id;
        updateProgress(35, 'Project uploaded. Starting multi-pass review... Please wait while loading...');
        pollScan(j.id, 0);
      } catch(err) {
        alert('Invalid response from server.');
      }
    } else if (xhr.status === 401) {
      // Auto-retry with fresh local token if unauthenticated
      try {
        const tokenRes = await fetch('/api/local-token');
        const tokenData = await tokenRes.json();
        if (tokenData.key) {
          $('apiKey').value = tokenData.key;
          updateProgress(10, 'Re-authenticating session... Please wait while loading...');
          const retryXhr = new XMLHttpRequest();
          retryXhr.open('POST', `/api/scan?fix=${fix}&llm=${llm}`);
          retryXhr.setRequestHeader('Authorization', 'Bearer ' + tokenData.key);
          retryXhr.upload.onprogress = xhr.upload.onprogress;
          retryXhr.onload = xhr.onload;
          retryXhr.onerror = xhr.onerror;
          retryXhr.send(activeFile);
          return;
        }
      } catch (e) {}
      alert('Authentication failed: missing or invalid API key.');
      $('statusTag').textContent='Ready';
    } else {
      let errMsg = 'Upload failed with status ' + xhr.status;
      try { errMsg = JSON.parse(xhr.responseText).error || errMsg; } catch(e){}
      alert(errMsg);
      $('statusTag').textContent='Ready';
    }
  };

  xhr.onerror = () => {
    alert('Connection error during upload. Please check server is running.');
    $('statusTag').textContent='Ready';
  };

  xhr.send(activeFile);
};

let activePollId = null;

async function pollScan(id, attempt){
  activePollId = id;
  if (attempt > 80) {
    $('statusLog').textContent = 'Scan timed out or is taking longer than expected. Please check server logs.';
    $('statusTag').textContent = 'Timed Out';
    return;
  }
  try{
    const r=await fetch('/api/scans/'+id,{headers:H()});
    if (activePollId !== id) return;
    if(r.status === 429) {
      // Rate limited: wait 3.5 seconds and retry gracefully
      return schedulePoll(()=>pollScan(id, attempt), 3500);
    }
    const j=await r.json();
    if(j.status==='queued'||j.status==='running'){
      attempt++;
      if (attempt === 1) {
        $('step-p0').className='step done';
        $('step-tests').className='step active';
        updateProgress(50, 'Analyzing project tree & running baseline tests... Please wait while loading...');
      } else if (attempt === 2) {
        $('step-tests').className='step done';
        $('step-p1').className='step active';
        updateProgress(70, 'Running AI line-level audit & Grounding gate... Please wait while loading...');
      } else if (attempt === 3) {
        $('step-p1').className='step done';
        $('step-ground').className='step done';
        $('step-p2').className='step active';
        updateProgress(85, 'Running Skeptic verification & QC checks... Please wait while loading...');
      } else {
        $('step-p2').className='step done';
        $('step-p5').className='step active';
        updateProgress(93, 'Generating scorecard and report... Please wait while loading...');
      }
      const nextDelay = attempt < 4 ? 2500 : (attempt < 15 ? 3500 : 5000);
      return schedulePoll(()=>pollScan(id, attempt), nextDelay);
    }
    if(j.status==='done'){
      updateProgress(100, 'Audit completed successfully.');
      finishScan(id, j);
    } else {
      $('statusLog').textContent='Scan error: '+(j.error||'Failed');
      $('statusTag').textContent='Error';
    }
  }catch(e){
    if (activePollId !== id) return;
    schedulePoll(()=>pollScan(id, attempt + 1), 3500);
  }
}

function finishScan(id, data){
  $('step-p0').className='step done';
  $('step-tests').className='step done';
  $('step-p1').className='step done';
  $('step-ground').className='step done';
  $('step-p2').className='step done';
  $('step-p5').className='step done';
  $('step-done').className='step done';
  $('statusTag').textContent='Completed';
  $('resultsCard').style.display='block';

  const sc = data.summary ? (data.summary.score_after || data.summary.score_before || {}) : {};
  const score = sc.overall !== undefined ? sc.overall : 85;
  const grade = sc.grade || 'B';
  const bandName = score>=80?'Good':score>=30?'NeedsWork':'CRITICAL';

  $('overallScore').textContent = score;
  $('overallGrade').textContent = 'Grade: '+grade;
  $('bandTag').textContent = bandName==='NeedsWork'?'Needs Work':bandName;
  $('bandTag').className = 'score-band band-'+bandName;

  $('detScore').textContent = (sc.deterministic_score !== undefined ? sc.deterministic_score : score)+'%';
  $('llmScore').textContent = (sc.llm_score !== undefined ? sc.llm_score : score)+'%';
  $('totalFindings').textContent = (data.summary && data.summary.findings_before) ? data.summary.findings_before.length : 'Verified';

  // Render findings
  const container = $('findingsContainer');
  container.innerHTML = '';
  const findings = (data.summary && (data.summary.findings_after || data.summary.findings_before)) || [];
  if(findings.length===0){
    container.innerHTML = '<div style="padding:16px;color:var(--muted)">No critical defects detected. Project passed quality gates.</div>';
  }else{
    findings.slice(0, 15).forEach(f=>{
      const div=document.createElement('div');
      div.className='finding-item';
      div.innerHTML=`
        <div class="finding-header">
          <span style="font-weight:600">${f.file}:${f.line}</span>
          <span class="sev-${f.severity}">${f.severity.toUpperCase()}</span>
        </div>
        <div style="font-size:14px;margin-bottom:6px">${f.message}</div>
        ${f.hint ? `<div class="evidence-quote">${f.hint}</div>` : ''}
      `;
      container.appendChild(div);
    });
  }

  // Setup download handlers
  $('dlPatch').onclick=()=>window.open(`/api/scans/${id}/report.patch?key=${getKey()}`);
  $('dlMd').onclick=()=>window.open(`/api/scans/${id}/report.md?key=${getKey()}`);
  $('dlHtml').onclick=()=>window.open(`/api/scans/${id}/report.html?key=${getKey()}`);
  $('dlJson').onclick=()=>window.open(`/api/scans/${id}/report.json?key=${getKey()}`);
}
</script>
</body>
</html>"""

CTYPES = {"html": "text/html; charset=utf-8", "md": "text/markdown; charset=utf-8",
          "json": "application/json", "patch": "text/plain; charset=utf-8"}


def make_handler(store: Store, settings: Settings, pool: ThreadPoolExecutor):
    import threading
    rate_limiter: Dict[str, List[float]] = {}
    rate_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = f"CodeGuard/{__version__}"

        def log_message(self, fmt, *args):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

        def _check_rate_limit(self) -> bool:
            ip = self.client_address[0] if hasattr(self, "client_address") else "127.0.0.1"
            now = time.time()
            with rate_lock:
                times = [t for t in rate_limiter.get(ip, []) if now - t < 30]
                if len(times) >= 60:
                    rate_limiter[ip] = times
                    return False
                times.append(now)
                rate_limiter[ip] = times
                return True

        def _send(self, code, body, ctype="application/json", extra=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body)
            body = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _err(self, code, msg):
            self._send(code, {"error": msg})

        def _account(self):
            h = self.headers.get("Authorization", "")
            if h.startswith("Bearer "):
                tok = h[7:].strip()
                if tok:
                    return store.authenticate(tok)
            q = parse_qs(urlparse(self.path).query)
            key_param = q.get("key", [""])[0]
            if key_param:
                return store.authenticate(key_param)
            return None

        def _body(self, limit):
            n = int(self.headers.get("Content-Length") or 0)
            if n > limit:
                return None
            return self.rfile.read(n)

        def do_GET(self):
            if not self._check_rate_limit():
                return self._send(429, {"error": "Rate limit exceeded. Please wait a moment."}, extra={"Retry-After": "2"})
            u = urlparse(self.path)
            if u.path == "/":
                local_key = store.create_key("local@codeguard.internal", "enterprise")
                html = DASHBOARD.replace("__DEFAULT_KEY__", local_key)
                return self._send(200, html, "text/html; charset=utf-8")
            if u.path == "/healthz":
                return self._send(200, {"ok": True, "version": __version__})
            if u.path == "/api/local-token":
                local_key = store.create_key("local@codeguard.internal", "enterprise")
                return self._send(200, {"key": local_key})
            if u.path in ("/favicon.ico", "/robots.txt"):
                return self._send(204, b"", "text/plain")
            acct = self._account()
            if not acct:
                return self._err(401, "missing or invalid API key")
            if u.path == "/api/usage":
                plan = PLANS[acct["plan"]]
                return self._send(200, {"plan": acct["plan"], "used_this_month": store.scans_this_month(acct["id"]),
                                        "limit": plan["scans_per_month"], "features": {"fix": plan["fix"], "llm": plan["llm"]}})
            m = re.fullmatch(r"/api/scans/([0-9a-f]{16})(?:/report\.(html|md|json|patch))?", u.path)
            if not m:
                return self._err(404, "not found")
            scan = store.get_scan(m.group(1))
            if not scan or scan["account_id"] != acct["id"]:
                return self._err(404, "not found")
            if not m.group(2):
                scan["summary"] = json.loads(scan["summary"]) if scan.get("summary") else None
                scan.pop("account_id", None)
                return self._send(200, scan)
            name = "codeguard-fixes.patch" if m.group(2) == "patch" else f"codeguard-report.{m.group(2)}"
            f = settings.data_dir / "scans" / scan["id"] / name
            if not f.is_file():
                return self._err(404, "report not available")
            extra = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"}
            return self._send(200, f.read_bytes(), CTYPES[m.group(2)], extra)

        def do_POST(self):
            if not self._check_rate_limit():
                return self._send(429, {"error": "Rate limit exceeded. Please wait a moment."}, extra={"Retry-After": "2"})
            u = urlparse(self.path)
            if u.path == "/webhooks/stripe":
                raw = self._body(1_000_000)
                if raw is None or not verify_stripe_signature(raw, self.headers.get("Stripe-Signature", ""), settings.stripe_secret):
                    return self._err(400, "invalid signature")
                try:
                    msg = apply_event(store, json.loads(raw))
                except ValueError:
                    return self._err(400, "bad payload")
                return self._send(200, {"received": True, "result": msg})
            if u.path == "/admin/keys":
                tok = self.headers.get("X-Admin-Token", "")
                if not settings.admin_token or not hmac.compare_digest(tok, settings.admin_token):
                    return self._err(403, "forbidden")
                try:
                    data = json.loads(self._body(10_000) or b"{}")
                    email, plan = str(data["email"]), data.get("plan", "free")
                except (ValueError, KeyError):
                    return self._err(400, 'expected JSON {"email": "...", "plan": "free|pro|enterprise"}')
                if plan not in PLANS:
                    return self._err(400, "unknown plan")
                return self._send(201, {"api_key": store.create_key(email, plan), "plan": plan})
            if u.path == "/api/scan":
                acct = self._account()
                if not acct:
                    content_len = int(self.headers.get("Content-Length") or 0)
                    if 0 < content_len < 20_000_000:
                        try:
                            self.rfile.read(content_len)
                        except Exception:
                            pass
                    return self._err(401, "missing or invalid API key")
                plan = PLANS[acct["plan"]]
                if quota_exceeded(acct["plan"], store.scans_this_month(acct["id"])):
                    return self._err(429, "monthly scan quota reached - upgrade your plan")
                data = self._body(plan["max_upload_mb"] * 1024 * 1024)
                if data is None:
                    return self._err(413, f"upload exceeds {plan['max_upload_mb']} MB for your plan")
                if not zipfile.is_zipfile(io.BytesIO(data)):
                    return self._err(400, "body must be a .zip archive")
                q = parse_qs(u.query)
                scan_id = secrets.token_hex(8)
                store.create_scan(acct["id"], scan_id)
                pool.submit(run_job, store, settings, scan_id, acct, data,
                            q.get("fix", ["0"])[0] == "1", q.get("llm", ["0"])[0] == "1")
                return self._send(202, {"id": scan_id, "status": "queued"})
            return self._err(404, "not found")

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8080):
    settings = Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(settings.data_dir / "codeguard.db")
    pool = ThreadPoolExecutor(max_workers=settings.workers)
    httpd = ThreadingHTTPServer((host, port), make_handler(store, settings, pool))
    print(f"CodeGuard {__version__} listening on http://{host}:{port}  (data: {settings.data_dir})", file=sys.stderr)
    if not settings.admin_token:
        print("warning: CODEGUARD_ADMIN_TOKEN not set - /admin/keys is disabled (use `codeguard keys`)", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        pool.shutdown(wait=False)
