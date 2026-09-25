#!/usr/bin/env python3
"""Live progress dashboard for the nonce-reuse scan. Binds 0.0.0.0:8080."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RESULTS = Path("/results")
HOST, PORT = "0.0.0.0", 8080

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Nonce Reuse Scan · blocks 210k–220k</title>
<style>
  :root {
    --bg: #07090d;
    --panel: #10151c;
    --ink: #d7e0ea;
    --muted: #7d8b99;
    --line: #1c2733;
    --amber: #e7b23a;
    --mint: #5ee0b5;
    --rose: #ff6b7a;
    --sky: #6cb6ff;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; background: var(--bg); color: var(--ink);
    font-family: "IBM Plex Sans", "Segoe UI", sans-serif; }
  body { min-height: 100dvh; background-image:
    radial-gradient(900px 400px at 10% -10%, #182230 0%, transparent 55%),
    linear-gradient(180deg, #07090d, #0b1016); }
  header { padding: 28px 32px 8px; display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
  .eyebrow { letter-spacing: .18em; text-transform: uppercase; font-size: 11px; color: var(--amber); }
  h1 { margin: 6px 0 0; font-size: 28px; font-weight: 650; letter-spacing: -0.03em; }
  .sub { color: var(--muted); margin-top: 6px; max-width: 62ch; line-height: 1.45; }
  .pill { border: 1px solid var(--line); background: #0d131b; padding: 8px 12px; border-radius: 999px;
    font-variant-numeric: tabular-nums; font-size: 13px; color: var(--mint); align-self: start; }
  main { padding: 16px 32px 48px; display: grid; gap: 16px; }
  .bar-wrap { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 18px 20px; }
  .bar-meta { display: flex; justify-content: space-between; font-size: 13px; color: var(--muted); margin-bottom: 10px; }
  .bar { height: 14px; background: #0a0e14; border-radius: 99px; overflow: hidden; border: 1px solid #222c38; }
  .bar > span { display: block; height: 100%; width: 0; background: linear-gradient(90deg, #2a6dff, #5ee0b5);
    box-shadow: 0 0 18px #5ee0b588; transition: width .4s ease; }
  .grid { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 12px; }
  @media (max-width: 900px) { .grid { grid-template-columns: repeat(2, minmax(0,1fr)); } header, main { padding-left: 16px; padding-right: 16px; } }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 16px 18px; }
  .k { font-size: 11px; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); }
  .v { font-size: 28px; font-weight: 650; margin-top: 6px; font-variant-numeric: tabular-nums; }
  .v.amber { color: var(--amber); } .v.mint { color: var(--mint); } .v.rose { color: var(--rose); } .v.sky { color: var(--sky); }
  pre { margin: 0; font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 12px; line-height: 1.55;
    color: #b7c4d0; max-height: 280px; overflow: auto; white-space: pre-wrap; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: var(--muted); font-weight: 500; padding: 8px 6px; border-bottom: 1px solid var(--line); }
  td { padding: 8px 6px; border-bottom: 1px solid #16202a; font-family: ui-monospace, monospace; font-size: 12px; }
  .note { color: var(--muted); font-size: 13px; line-height: 1.5; }
</style>
</head>
<body>
<header>
  <div>
    <div class="eyebrow">Bitcoin ECDSA forensics</div>
    <h1>Nonce reuse scan · 210,000–220,000</h1>
    <p class="sub">Legacy P2PKH / P2SH signatures. Same (pubkey, r) groups are recovered to private keys when the extractor can prove d·G = P.</p>
  </div>
  <div class="pill" id="status">connecting…</div>
</header>
<main>
  <section class="bar-wrap">
    <div class="bar-meta">
      <span id="hlabel">height —</span>
      <span id="pct">0%</span>
    </div>
    <div class="bar"><span id="bar"></span></div>
  </section>
  <section class="grid">
    <div class="card"><div class="k">Blocks</div><div class="v" id="blocks">0</div></div>
    <div class="card"><div class="k">Transactions</div><div class="v sky" id="txs">0</div></div>
    <div class="card"><div class="k">Valid signatures</div><div class="v mint" id="sigs">0</div></div>
    <div class="card"><div class="k">Keys recovered</div><div class="v amber" id="keys">0</div></div>
    <div class="card"><div class="k">Reuse groups</div><div class="v rose" id="reuse">0</div></div>
    <div class="card"><div class="k">Inputs scanned</div><div class="v" id="inputs">0</div></div>
    <div class="card"><div class="k">Failed blocks</div><div class="v" id="failed">0</div></div>
    <div class="card"><div class="k">Mode</div><div class="v" id="mode" style="font-size:18px;padding-top:8px">—</div></div>
  </section>
  <section class="card">
    <div class="k">Heartbeat / log</div>
    <pre id="log">waiting for scanner…</pre>
  </section>
  <section class="card">
    <div class="k">Reuse hits (private keys stored only on disk, not shown here)</div>
    <div style="overflow:auto;margin-top:8px">
      <table>
        <thead><tr><th>pubkey</th><th>r</th><th>blocks</th><th>recovered</th></tr></thead>
        <tbody id="hits"><tr><td colspan="4" class="note">None yet — expected for this range; the Android SecureRandom bug postdates 220,000.</td></tr></tbody>
      </table>
    </div>
  </section>
  <p class="note">Nothing is broadcast, moved, or spent. This dashboard is a live view of a historical chain scan.</p>
</main>
<script>
const START=210000, END=220000, SPAN=END-START+1;
const fmt=n=>Intl.NumberFormat().format(n||0);
async function tick(){
  try{
    const p=await (await fetch('/api/progress')).json();
    const log=await (await fetch('/api/log')).text();
    const hits=await (await fetch('/api/reuse')).json();
    const h=p.last_completed_height||START-1;
    const done=Math.max(0, Math.min(SPAN, (h-START+1)));
    const pct=Math.max(0, Math.min(100, done/SPAN*100));
    document.getElementById('bar').style.width=pct+'%';
    document.getElementById('pct').textContent=pct.toFixed(2)+'%';
    document.getElementById('hlabel').textContent='height '+fmt(h)+' / '+fmt(END);
    document.getElementById('blocks').textContent=fmt(p.blocks_scanned);
    document.getElementById('txs').textContent=fmt(p.txs_scanned);
    document.getElementById('sigs').textContent=fmt(p.valid_sigs);
    document.getElementById('keys').textContent=fmt(p.keys_recovered);
    document.getElementById('reuse').textContent=fmt(p.reuse_groups);
    document.getElementById('inputs').textContent=fmt(p.inputs_scanned);
    document.getElementById('failed').textContent=fmt(p.failed_blocks);
    document.getElementById('mode').textContent=p.mode||'—';
    const live=h>=END ? 'complete' : (p.calibration==='pass'?'scanning':'calibrating');
    document.getElementById('status').textContent=live+' · '+ (p.updated_at||'');
    document.getElementById('log').textContent=log || 'no log yet';
    const tb=document.getElementById('hits');
    if(hits.length){
      tb.innerHTML=hits.map(x=>`<tr><td>${x.pubkey}</td><td>${x.r}</td><td>${x.blocks}</td><td>${x.recovered}</td></tr>`).join('');
    }
  }catch(e){ document.getElementById('status').textContent='waiting for results'; }
}
tick(); setInterval(tick, 2000);
</script>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            self._send(200, HTML.encode(), "text/html; charset=utf-8")
            return
        if self.path == "/api/progress":
            path = RESULTS / "progress.json"
            body = path.read_bytes() if path.exists() else b"{}"
            self._send(200, body, "application/json")
            return
        if self.path == "/api/log":
            path = RESULTS / "scan.log"
            if not path.exists():
                self._send(200, b"", "text/plain; charset=utf-8")
                return
            data = path.read_bytes()
            # last ~8kb
            self._send(200, data[-8000:], "text/plain; charset=utf-8")
            return
        if self.path == "/api/reuse":
            path = RESULTS / "nonce_reuse.jsonl"
            hits = []
            if path.exists():
                with open(path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except Exception:
                            continue
                        mem = rec.get("members") or []
                        blocks = ",".join(str(m.get("block_height", "")) for m in mem[:4])
                        pk = rec.get("pubkey_hex") or ""
                        r = rec.get("r") or ""
                        hits.append(
                            {
                                "pubkey": pk[:16] + "…" if len(pk) > 16 else pk,
                                "r": r[:16] + "…" if len(r) > 16 else r,
                                "blocks": blocks,
                                "recovered": bool(rec.get("recovered")),
                            }
                        )
                        if len(hits) >= 20:
                            break
            self._send(200, json.dumps(hits).encode(), "application/json")
            return
        self._send(404, b"not found", "text/plain")


def main() -> None:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"dashboard on {HOST}:{PORT}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
