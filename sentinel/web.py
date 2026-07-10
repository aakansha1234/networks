"""Optional web dashboard for Sentinel (FastAPI).

Install and run:
    uv sync --extra web
    sentinel web                     # http://localhost:8000

Exposes a single-page dashboard: paste a config (or load a bundled example),
see the posture score, severity breakdown, the findings table, and the
generated remediation script. An optional plain-language summary is available
when an LLM endpoint is configured.
"""
from __future__ import annotations

from pydantic import BaseModel

from .finding import ScanResult
from .parsers import parse
from .remediate import remediation_script
from .rules import run as run_rules


class ScanReq(BaseModel):
    """Request body for the /scan and /summary endpoints (module-scoped for FastAPI)."""
    config: str

# -- bundled example configs (ship with the app so it demos standalone) --------
_EXAMPLE_IOS = """!
version 15.7
service timestamps debug datetime msec
!
hostname branch-rtr-01
!
ip ssh version 1
ip http server
ip http secure-server
!
ip access-list extended OUTSIDE-IN
 permit tcp any host 10.0.0.1 eq 443
 permit ip any any
!
snmp-server community public RO
snmp-server community private RW
!
interface GigabitEthernet0/0
 ip address 203.0.113.2 255.255.255.252
 ip access-group OUTSIDE-IN in
 no shutdown
!
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
line vty 0 4
 transport input telnet ssh
 password 7 0822458D0A76
 login
!
end
"""

_EXAMPLE_PANOS = """set deviceconfig system hostname pa-fw-01
set deviceconfig system ip-address 10.0.0.1
set network interface ethernet ethernet1/1 layer3 ip 203.0.113.2/24
set network interface ethernet ethernet1/2 layer3 ip 192.168.1.1/24
set zone untrust network layer3 ethernet1/1
set zone trust network layer3 ethernet1/2
set address server-1 ip-netmask 192.168.1.10/32
set service web-443 tcp 443
set rulebase security allow-any-any from any to any source any destination any application any service any action allow
set rulebase security allow-rdp from untrust to trust source any destination any application any service application-default action allow log-end yes
set rulebase security allow-web from untrust to trust source any destination server-1 application web-browsing service web-443 action allow log-end yes
"""

EXAMPLES = {
    "Cisco IOS — branch router (flawed)": _EXAMPLE_IOS,
    "Palo Alto PAN-OS — edge firewall (flawed)": _EXAMPLE_PANOS,
}


def scan_payload(text: str) -> dict:
    """Run the full audit and return a JSON-serialisable payload."""
    device = parse(text)
    findings = run_rules(device)
    result = ScanResult(device=device, findings=findings)
    return {
        "device": {
            "hostname": device.hostname, "vendor": device.vendor,
            "os": device.os, "version": device.version,
        },
        "summary": {"score": result.score, "counts": result.counts},
        "findings": [f.to_dict() for f in result.sorted()],
        "remediation": remediation_script(findings, device.hostname) if findings else "",
    }


def create_app():  # pragma: no cover - exercised via `sentinel web`
    from fastapi import Body, FastAPI
    from fastapi.responses import HTMLResponse, JSONResponse

    app = FastAPI(title="Sentinel", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return INDEX_HTML

    @app.get("/api/examples")
    def examples() -> dict:
        return {"examples": list(EXAMPLES.keys())}

    @app.post("/api/load-example")
    def load_example(name: str) -> dict:
        return {"config": EXAMPLES.get(name, "")}

    @app.post("/api/scan")
    def api_scan(req: ScanReq = Body(...)):
        try:
            return scan_payload(req.config)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse({"error": str(exc)}, status_code=400)

    @app.post("/api/summary")
    def api_summary(req: ScanReq = Body(...)):
        from .agent import summarize
        from .llm import LLMError, get_client
        client = get_client()
        if client is None:
            return {"summary": None, "reason": "no LLM API key configured"}
        device = parse(req.config)
        findings = run_rules(device)
        try:
            return {"summary": summarize(device, findings, client), "reason": None}
        except LLMError as exc:
            return {"summary": None, "reason": str(exc)}

    return app


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:  # pragma: no cover
    import uvicorn
    uvicorn.run(create_app(), host=host, port=port)


# -- dashboard (single file, no build step) -----------------------------------
_INDEX_CSS = """
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  background:#0d1117;color:#c9d1d9;line-height:1.5}
header{padding:18px 28px;border-bottom:1px solid #30363d;display:flex;align-items:center;gap:12px}
.brand{font-size:20px;font-weight:700;color:#58a6ff}
.brand small{color:#8b949e;font-weight:400;margin-left:8px}
main{max-width:1100px;margin:0 auto;padding:24px 28px}
.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin-bottom:18px}
textarea{width:100%;height:180px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;
  border-radius:8px;padding:12px;font-family:ui-monospace,Menlo,monospace;font-size:13px}
.row{display:flex;gap:10px;align-items:center;margin-top:10px;flex-wrap:wrap}
button,.btn{background:#238636;color:#fff;border:none;border-radius:6px;padding:8px 16px;
  font-size:14px;cursor:pointer;font-weight:600}
button:hover{background:#2ea043}
button.secondary{background:#21262d;color:#c9d1d9;border:1px solid #30363d}
select{background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:7px 10px;font-size:14px}
.scorebox{display:flex;align-items:center;gap:24px;flex-wrap:wrap}
.score{font-size:42px;font-weight:800;line-height:1}
.score small{font-size:14px;color:#8b949e;font-weight:400}
.badges{display:flex;gap:8px;flex-wrap:wrap}
.badge{padding:4px 10px;border-radius:20px;font-size:13px;font-weight:600}
.b-critical{background:rgba(255,107,107,.15);color:#ff6b6b;border:1px solid rgba(255,107,107,.4)}
.b-high{background:rgba(255,140,102,.15);color:#ff8c66;border:1px solid rgba(255,140,102,.4)}
.b-medium{background:rgba(240,198,116,.15);color:#f0c674;border:1px solid rgba(240,198,116,.4)}
.b-low{background:rgba(121,192,255,.15);color:#79c0ff;border:1px solid rgba(121,192,255,.4)}
.ok{color:#3fb950;font-weight:600}
table{width:100%;border-collapse:collapse;margin-top:6px}
th{text-align:left;color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:.5px;
  padding:8px 10px;border-bottom:1px solid #30363d}
td{padding:10px;border-bottom:1px solid #21262d;font-size:14px;vertical-align:top}
.sev{font-weight:700}
.s-critical{color:#ff6b6b}.s-high{color:#ff8c66}.s-medium{color:#f0c674}.s-low{color:#79c0ff}
.mono{font-family:ui-monospace,Menlo,monospace}
pre{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:14px;overflow:auto;
  font-size:13px;color:#c9d1d9}
h3{margin:0 0 4px;font-size:15px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px}
.error{color:#ff6b6b}
.muted{color:#8b949e}
.ai{border-left:3px solid #bc8cff;padding-left:14px;color:#d2a8ff}
"""

_INDEX_JS = """
const $ = (s)=>document.querySelector(s);
const sevClass = {critical:'s-critical',high:'s-high',medium:'s-medium',low:'s-low'};
const badgeClass = {critical:'b-critical',high:'b-high',medium:'b-medium',low:'b-low'};
async function post(url, body){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return r.json();}
async function loadExamples(){
  const d=await fetch('/api/examples').then(r=>r.json());
  const sel=$('#example');d.examples.forEach(e=>{const o=document.createElement('option');o.value=e;o.textContent=e;sel.appendChild(o);});
}
$('#example').addEventListener('change', async (e)=>{
  if(!e.target.value) return;
  const d=await post('/api/load-example?name='+encodeURIComponent(e.target.value),{});
  $('#cfg').value=d.config;
});
$('#scanBtn').addEventListener('click', async ()=>{
  const cfg=$('#cfg').value.trim(); if(!cfg){return;}
  $('#results').hidden=true; $('#err').textContent='';
  const d=await post('/api/scan',{config:cfg});
  if(d.error){$('#err').textContent=d.error;return;}
  render(d);
});
$('#aiBtn').addEventListener('click', async ()=>{
  const cfg=$('#cfg').value.trim(); if(!cfg){return;}
  $('#ai').innerHTML='<span class="muted">thinking…</span>';
  const d=await post('/api/summary',{config:cfg});
  $('#ai').textContent = d.summary || ('('+d.reason+')');
});
function render(d){
  const dev=d.device, s=d.summary;
  $('#dev').textContent=`${dev.hostname} · ${dev.vendor}/${dev.os} ${dev.version||''}`;
  const sc=s.score; $('#score').textContent=sc;
  $('#score').style.color = sc>=80?'#3fb950':sc>=50?'#f0c674':'#ff6b6b';
  const c=s.counts;
  let badges='';
  for(const k of ['critical','high','medium','low']){if(c[k])badges+=`<span class="badge ${badgeClass[k]}">${c[k]} ${k}</span>`;}
  $('#badges').innerHTML=badges||'<span class="ok">clean</span>';
  const tb=$('#findings');
  if(!d.findings.length){tb.innerHTML='<tr><td class="ok">No findings — config looks clean.</td></tr>';}
  else{tb.innerHTML=d.findings.map(f=>`<tr>
    <td class="mono muted">${f.rule_id}</td>
    <td class="sev ${sevClass[f.severity]||''}">${f.severity}</td>
    <td>${f.title}<div class="muted" style="font-size:12px;margin-top:2px">${f.evidence}${f.line?' · line '+f.line:''}</div></td>
    <td>${f.cis_ref||''}</td></tr>`).join('');}
  $('#remediation').textContent=d.remediation||'(no remediation needed)';
  $('#results').hidden=false;
}
loadExamples();
"""

INDEX_HTML = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Sentinel — Network Config Security Auditor</title>
<style>{_INDEX_CSS}</style>
</head><body>
<header><span class="brand">Sentinel<small>network config security auditor</small></span></header>
<main>
  <div class="panel">
    <h3>Configuration</h3>
    <textarea id="cfg" spellcheck="false" placeholder="Paste a Cisco IOS or Palo Alto PAN-OS config…"></textarea>
    <div class="row">
      <button id="scanBtn">Scan</button>
      <button id="aiBtn" class="secondary">Summary</button>
      <select id="example"><option value="">Load example…</option></select>
    </div>
    <div id="err" class="error"></div>
  </div>

  <div id="results" hidden>
    <div class="panel">
      <div class="scorebox">
        <div><div class="muted" id="dev"></div>
          <div style="margin-top:8px"><span class="score" id="score">—</span><small> /100 posture score</small></div></div>
        <div id="badges" class="badges"></div>
      </div>
    </div>
    <div class="panel">
      <h3>Findings</h3>
      <table><thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>CIS</th></tr></thead>
        <tbody id="findings"></tbody></table>
    </div>
    <div class="panel">
      <h3>Remediation script</h3>
      <pre id="remediation"></pre>
    </div>
    <div class="panel" id="aiPanel" hidden><h3>Summary</h3><div id="ai" class="ai"></div></div>
  </div>
</main>
<script>{_INDEX_JS}</script>
</body></html>
"""
