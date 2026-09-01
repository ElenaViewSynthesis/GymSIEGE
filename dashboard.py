#!/usr/bin/env python3
"""
GYMSIEGE live dashboard (§4/§6 Phase 6).

A small FastAPI app that reads results.json, results/concurrency_sweep.json,
results/provisioning_bench.json and recordings/*.mp4 straight off disk and
renders:
  - a live results table (polls every 4s)
  - the concurrency failure curve (the money chart)
  - a cold-start histogram split by provisioning mode (snapshot/cold/fork)
  - per-sandbox CPU/mem time-series
  - a pass@k leaderboard
  - links to each trial's recorded .mp4

Two ways to run it:

  Local (fastest for iterating on the dashboard itself):
      uvicorn dashboard:app --host 0.0.0.0 --port 8000

  Inside a Daytona sandbox, exposed via a real preview link (what §4/§9
  actually asks for — "served via get_preview_link(8000)"):
      python dashboard.py --publish

  --publish creates (or reuses, via --sandbox-id) a small Daytona sandbox,
  uploads this file plus the current results/*.json and recordings/, starts
  uvicorn inside it with process.exec, and prints the preview URL from
  sandbox.get_preview_link(8000). It intentionally does NOT try to keep the
  dashboard's live results in sync with a still-running orchestrator on a
  different machine — for a same-host run, mount/refresh results.json into
  the dashboard sandbox before publishing (see README "Running the
  dashboard").
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import common
from common import (
    CONCURRENCY_SWEEP_JSON,
    PROVISIONING_BENCH_JSON,
    RECORDINGS_DIR,
    RESULTS_JSON,
    EXPLOITGYM_RESULTS_JSON,
    get_logger,
    load_json,
    read_events,
)

log = get_logger("dashboard")

app = FastAPI(title="GYMSIEGE Dashboard")
if RECORDINGS_DIR.exists():
    app.mount("/recordings", StaticFiles(directory=str(RECORDINGS_DIR)), name="recordings")


@app.get("/api/results")
def api_results() -> JSONResponse:
    return JSONResponse(load_json(RESULTS_JSON, {"status": "not yet run", "trials": [], "pass_at_k": {}, "capability": {}}))


@app.get("/api/exploitgym")
def api_exploitgym() -> JSONResponse:
    return JSONResponse(
        load_json(
            EXPLOITGYM_RESULTS_JSON,
            {"status": "not yet run", "trials": [], "pass_at_k": {}},
        )
    )


@app.get("/api/sweep")
def api_sweep() -> JSONResponse:
    return JSONResponse(load_json(CONCURRENCY_SWEEP_JSON, {"levels": []}))


@app.get("/api/provisioning")
def api_provisioning() -> JSONResponse:
    bench = load_json(PROVISIONING_BENCH_JSON, {"bake": [], "cold_create": [], "snapshot_create": [], "fork_create": []})
    out = {}
    for key in ("cold_create", "snapshot_create", "fork_create", "exploitgym_snapshot_create"):
        xs = sorted(x["duration_s"] for x in bench.get(key, []))
        out[key] = {
            "samples": xs,
            "p50": _pctile(xs, 50),
            "p95": _pctile(xs, 95),
            "n": len(xs),
        }
    out["bake"] = bench.get("bake", [])
    return JSONResponse(out)


@app.get("/api/telemetry/{sandbox_id}")
def api_telemetry(sandbox_id: str) -> JSONResponse:
    for path in (RESULTS_JSON, EXPLOITGYM_RESULTS_JSON):
        results = load_json(path, {"trials": []})
        for t in results.get("trials", []):
            if t.get("sandbox_id") == sandbox_id:
                return JSONResponse({"metrics_latest": t.get("metrics_latest"), "metrics_series": t.get("metrics_series")})
    return JSONResponse({"metrics_latest": None, "metrics_series": []})


@app.get("/api/events")
def api_events(limit: int = 200) -> JSONResponse:
    return JSONResponse(read_events(limit))


def _pctile(xs: list[float], p: float):
    if not xs:
        return None
    idx = min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))
    return xs[idx]


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _PAGE


_PAGE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>GYMSIEGE</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, Segoe UI, sans-serif; margin: 0; padding: 24px;
         background: #0d1117; color: #e6edf3; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .sub { color: #8b949e; font-size: 13px; margin-bottom: 20px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
  .card h2 { font-size: 14px; margin: 0 0 12px; color: #8b949e; text-transform: uppercase; letter-spacing: .04em; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #21262d; }
  th { color: #8b949e; font-weight: 500; }
  .status-success { color: #3fb950; }
  .status-failed, .status-error { color: #f85149; }
  .status-other_vuln { color: #d29922; }
  .status-running, .status-pending { color: #58a6ff; }
  .bignum { font-size: 28px; font-weight: 600; }
  .barrow { display: flex; align-items: center; gap: 8px; margin: 4px 0; font-size: 12px; }
  .bar { height: 14px; background: #388bfd; border-radius: 3px; }
  .bar.timeout { background: #d29922; }
  .bar.oom { background: #f85149; }
  a { color: #58a6ff; }
  .full { grid-column: 1 / -1; }
</style>
</head>
<body>
<h1>GYMSIEGE</h1>
<div class="sub">CyberGym-E2E + ExploitGym on a Daytona sandbox fleet — capability eval + infra stress harness</div>

<div class="grid">
  <div class="card"><h2>pass@k leaderboard</h2><div id="leaderboard"></div></div>
  <div class="card"><h2>capability</h2><div id="capability"></div></div>
  <div class="card full"><h2>ExploitGym (hardened + firewall)</h2><div id="exploitgym"></div></div>
  <div class="card full"><h2>concurrency failure curve</h2><div id="sweep"></div></div>
  <div class="card"><h2>provisioning latency (p50 / p95, seconds)</h2><div id="provisioning"></div></div>
  <div class="card"><h2>results table</h2><div id="results" style="max-height:360px;overflow:auto"></div></div>
  <div class="card full"><h2>per-sandbox CPU / memory telemetry</h2><div id="telemetry"></div></div>
  <div class="card full"><h2>recordings</h2><div id="recordings"></div></div>
</div>

<script>
async function j(url) { const r = await fetch(url); return r.json(); }

function fmt(x, d) { return (x === null || x === undefined) ? "—" : Number(x).toFixed(d ?? 1); }

async function renderResults() {
  const [data, exploit] = await Promise.all([j('/api/results'), j('/api/exploitgym')]);
  const trials = (data.trials || []).concat(exploit.trials || []);

  const leaders = Object.entries(data.pass_at_k || {}).concat(
    exploit.pass_at_k && exploit.pass_at_k.n_tasks ? [['exploitgym', exploit.pass_at_k]] : []
  );
  document.getElementById('leaderboard').innerHTML = leaders.map(([mode, v]) => `
    <div style="margin-bottom:10px">
      <div style="font-size:12px;color:#8b949e">${mode} (n=${v.n_tasks} tasks, k=${v.k})</div>
      <div class="bignum">${fmt(v.pass_at_k*100,0)}%<span style="font-size:13px;color:#8b949e"> pass@k</span></div>
      <div style="font-size:12px;color:#8b949e">pass@1: ${fmt(v.pass_at_1*100,0)}%</div>
    </div>`).join('') || '<span style="color:#8b949e">no trials yet</span>';

  const cap = data.capability || {};
  document.getElementById('capability').innerHTML = Object.entries(cap).map(([k,v]) =>
    `<div style="display:flex;justify-content:space-between;font-size:13px;padding:2px 0">
       <span>${k}</span><span>${typeof v === 'number' ? (v<=1 ? fmt(v*100,0)+'%' : fmt(v,0)) : v}</span>
     </div>`).join('') || '<span style="color:#8b949e">no trials yet</span>';

  const eg = exploit.pass_at_k || {};
  document.getElementById('exploitgym').innerHTML = eg.n_tasks ?
    `<div class="bignum">${fmt(eg.pass_at_k*100,0)}%<span style="font-size:13px;color:#8b949e"> pass@${eg.k}</span></div>
     <div style="font-size:12px;color:#8b949e">${eg.n_tasks} tasks · pass@1 ${fmt(eg.pass_at_1*100,0)}% · cost ${fmt(exploit.total_solver_cost_usd,2)} USD</div>` :
    '<span style="color:#8b949e">ExploitGym not run yet</span>';

  document.getElementById('results').innerHTML = `<table><thead><tr>
      <th>benchmark</th><th>task</th><th>mode</th><th>trial</th><th>status</th><th>score/stages</th><th>t_total</th><th>artifacts</th>
    </tr></thead><tbody>` +
    trials.slice().reverse().map(t => `<tr>
      <td>${t.benchmark||'cybergym-e2e'}</td><td>${t.task}</td><td>${t.mode}</td><td>${t.trial}</td>
      <td class="status-${t.status}">${t.status}</td>
      <td>${t.score!==undefined && t.score!==null ? fmt(t.score,2) : ['stage1','stage2','stage3','stage4'].map(s=>t[s]?`${s.slice(-1)}:${t[s][0]}`:'').filter(Boolean).join(' ')}</td>
      <td>${fmt(t.t_total_s,0)}s</td>
      <td>${t.poc_url?`<a href="${t.poc_url}" target=_blank>poc</a> `:''}${t.patch_url?`<a href="${t.patch_url}" target=_blank>patch</a> `:''}${t.recording_path?`<a href="/recordings/${t.recording_path.split(/[\\\\/]/).pop()}" target=_blank>mp4</a>`:''}</td>
    </tr>`).join('') + `</tbody></table>`;

  document.getElementById('recordings').innerHTML = trials.filter(t=>t.recording_path).map(t =>
    `<div style="display:inline-block;margin:6px"><a href="/recordings/${t.recording_path.split(/[\\\\/]/).pop()}" target=_blank>${t.task} (${t.mode} t${t.trial})</a></div>`
  ).join('') || '<span style="color:#8b949e">no recordings yet</span>';

  const telemetry = trials.filter(t => (t.metrics_series||[]).length).slice(-8);
  document.getElementById('telemetry').innerHTML = telemetry.map(t => telemetryChart(t)).join('') ||
    '<span style="color:#8b949e">no telemetry yet</span>';
}

function telemetryChart(t) {
  const samples = t.metrics_series || [];
  const width=320, height=90, pad=8;
  const cpu = samples.map(s=>Number(s.cpu_used_pct||0));
  const mem = samples.map(s=>Number(s.mem_total||0)>0 ? 100*Number(s.mem_used||0)/Number(s.mem_total) : 0);
  function points(values) { return values.map((v,i)=>`${pad+i*(width-2*pad)/Math.max(values.length-1,1)},${height-pad-Math.min(100,v)*(height-2*pad)/100}`).join(' '); }
  return `<div style="display:inline-block;margin:8px;vertical-align:top"><div style="font-size:11px;color:#8b949e">${t.task} t${t.trial}</div>
    <svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" style="background:#0d1117;border:1px solid #30363d">
      <polyline points="${points(cpu)}" fill="none" stroke="#58a6ff" stroke-width="2"/>
      <polyline points="${points(mem)}" fill="none" stroke="#f0883e" stroke-width="2"/>
    </svg><div style="font-size:10px"><span style="color:#58a6ff">CPU%</span> · <span style="color:#f0883e">memory%</span></div></div>`;
}

async function renderSweep() {
  const data = await j('/api/sweep');
  const levels = data.levels || [];
  document.getElementById('sweep').innerHTML = levels.map(l => `
    <div class="barrow">
      <div style="width:40px">N=${l.level}</div>
      <div class="bar" style="width:${(l.success_rate||0)*240}px"></div>
      <div>${fmt((l.success_rate||0)*100,0)}% success</div>
      <div style="color:#8b949e">p95 create ${fmt(l.create_latency_p95_s,1)}s</div>
      ${l.timeout_rate ? `<div style="color:#d29922">${fmt(l.timeout_rate*100,0)}% timeout</div>` : ''}
      ${l.oom_rate ? `<div style="color:#f85149">${fmt(l.oom_rate*100,0)}% OOM</div>` : ''}
    </div>`).join('') + (data.knee_level ? `<div style="margin-top:8px;color:#d29922">knee at N=${data.knee_level}</div>` : '')
    || '<span style="color:#8b949e">sweep not run yet — orchestrator.py sweep</span>';
}

async function renderProvisioning() {
  const data = await j('/api/provisioning');
  const rows = ['cold_create','snapshot_create','fork_create','exploitgym_snapshot_create'].map(k => {
    const d = data[k] || {};
    return `<div class="barrow"><div style="width:120px">${k.replace('_create','')}</div>
      <div class="bar" style="width:${Math.min((d.p95||0)*4,240)}px"></div>
      <div>p50 ${fmt(d.p50,1)}s / p95 ${fmt(d.p95,1)}s (n=${d.n||0})</div></div>`;
  }).join('');
  document.getElementById('provisioning').innerHTML = rows;
}

async function tick() {
  try { await Promise.all([renderResults(), renderSweep(), renderProvisioning()]); }
  catch (e) { console.error(e); }
}
tick();
setInterval(tick, 4000);
</script>
</body>
</html>"""


# --------------------------------------------------------------------------
# `python dashboard.py --publish` — run this dashboard inside a real Daytona
# sandbox and hand back a get_preview_link(8000) URL.
# --------------------------------------------------------------------------


async def publish(sandbox_id: str | None) -> None:
    from daytona import AsyncDaytona, CreateSandboxFromImageParams, Image

    common.require_env("DAYTONA_API_KEY")
    async with AsyncDaytona() as daytona:
        if sandbox_id:
            sandbox = await daytona.get(sandbox_id)
            log.info("reusing dashboard sandbox %s", sandbox.id)
        else:
            sandbox = await daytona.create(
                CreateSandboxFromImageParams(
                    image=Image.debian_slim(),
                    name="siege-dashboard",
                    ttl_minutes=common.SANDBOX_SAFETY_TTL_MINUTES,
                ),
                timeout=300,
            )
            log.info("created dashboard sandbox %s", sandbox.id)

        await sandbox.set_ttl(common.SANDBOX_SAFETY_TTL_MINUTES)

        await sandbox.process.exec("python3 -m pip install --break-system-packages fastapi 'uvicorn[standard]'")
        await sandbox.process.exec("mkdir -p /home/daytona/results /home/daytona/recordings")

        for relpath in ["dashboard.py", "common.py", "results.json"]:
            p = common.ROOT / relpath
            if p.exists():
                await sandbox.fs.upload_file(str(p), f"/home/daytona/{relpath}")
        for sub in ["results", "recordings"]:
            d = common.ROOT / sub
            if d.exists():
                for f in d.rglob("*"):
                    if f.is_file():
                        rel = f.relative_to(common.ROOT)
                        await sandbox.fs.upload_file(str(f), f"/home/daytona/{rel.as_posix()}")

        await sandbox.process.exec(
            "cd /home/daytona && nohup python3 -m uvicorn dashboard:app --host 0.0.0.0 --port 8000 "
            "> dashboard.log 2>&1 &"
        )
        await asyncio.sleep(2)

        preview = await sandbox.get_preview_link(8000)
        print(f"GYMSIEGE dashboard live at: {preview.url}")
        print(f"sandbox id: {sandbox.id}  (pass --sandbox-id {sandbox.id} to redeploy without recreating)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--publish", action="store_true", help="run inside a real Daytona sandbox and print the preview link")
    parser.add_argument("--sandbox-id", default=None, help="reuse an existing dashboard sandbox")
    args = parser.parse_args()
    if args.publish:
        asyncio.run(publish(args.sandbox_id))
    else:
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000)
