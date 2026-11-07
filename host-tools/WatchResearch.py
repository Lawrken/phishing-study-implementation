"""Loopback-only, view-only display of VM browser snapshots and measured status."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path


HTML = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Research VM — view only</title>
<style>body{font:16px system-ui;background:#111720;color:#e8eef7;margin:0;padding:24px}main{max-width:1100px;margin:auto}h1{font-size:24px;margin:0 0 8px}p{color:#b8c6d8}header{display:flex;gap:24px;flex-wrap:wrap;align-items:center}section{margin:20px 0}#meters{display:flex;gap:28px;flex-wrap:wrap}.value{font-size:26px;font-weight:600}img{width:100%;height:auto;background:#17212e;border-radius:8px;pointer-events:none}#empty{padding:70px 20px;text-align:center;background:#17212e;border-radius:8px}dl{display:grid;grid-template-columns:170px 1fr;gap:10px}dd{margin:0;overflow-wrap:anywhere}dt{color:#b8c6d8}#stage{font-weight:600}small{color:#b8c6d8}progress{width:160px;accent-color:#58c6ba}@media(max-width:500px){body{padding:14px}dl{grid-template-columns:1fr}dd{margin-bottom:10px}}</style>
<main><header><div><h1>Research VM</h1><small>View only · actual VM browser snapshots · refresh about every 5 seconds</small></div><strong id="vmstate">Waiting for VM</strong></header>
<section id="meters"><div><small>Additional usable phishing captures</small><div class="value" id="captures">0 / 59</div><progress id="progress" max="59" value="0"></progress></div><div><small>New campaign attempts</small><div class="value" id="attempts">0 / 800</div></div><div><small>Balanced professor target</small><div class="value" id="balanced">91 / 150</div></div></section>
<section><div id="stage">Preparing the separately approved campaign</div><p id="note">A browser image will appear during an allowed website visit. Published labels are separate from current page status.</p><div id="empty">The VM browser has not started a new website visit.</div><img id="frame" alt="Latest screenshot of the browser running inside the research VM" hidden></section>
<section><h2>VM and verification status</h2><dl><dt>Run</dt><dd id="run">Pending</dd><dt>Guest uptime</dt><dd id="uptime">Pending</dd><dt>Guest available RAM</dt><dd id="memory">Pending</dd><dt>Windows available RAM</dt><dd id="hostram">Pending</dd><dt>Verification</dt><dd id="verification">Pending</dd><dt>Updated</dt><dd id="updated">Pending</dd></dl></section></main>
<script>const byId=id=>document.getElementById(id);async function update(){try{const r=await fetch('/state.json',{cache:'no-store'});const s=await r.json();let n=s.counts?.usable_per_class?.phishing||0;byId('captures').textContent=n+' / 59';byId('progress').value=n;byId('attempts').textContent=(s.counts?.attempts||0)+' / 800';byId('balanced').textContent=(75+Math.min(75,16+n))+' / 150';byId('vmstate').textContent=s.vm_running?'VM running':(s.finished?'VM stopped':'Waiting for VM');byId('run').textContent=s.run_id||'Pending';byId('uptime').textContent=s.vm?.uptime?Math.round(Number(s.vm.uptime))+' seconds':'Pending';byId('memory').textContent=s.vm?.memory_available_kib?(Number(s.vm.memory_available_kib)/1048576).toFixed(2)+' GiB':'Pending';byId('hostram').textContent=s.host_available_ram_gib?Number(s.host_available_ram_gib).toFixed(2)+' GiB':'Pending';byId('verification').textContent=Object.entries(s.verification||{}).map(([k,v])=>k+': '+v).join(' · ')||'Checks pending';byId('updated').textContent=s.utc?new Date(s.utc).toLocaleString():'Pending';byId('stage').textContent=s.finished?'Campaign stopped — '+(s.stop_reason||'see report'):(s.view?.stage||'Deployment verification before dataset visits');if(s.frame_present){byId('frame').src='/frame.jpg?t='+Date.now();byId('frame').hidden=false;byId('empty').hidden=true}byId('note').textContent=s.view?.candidate_id?'Endpoint ID '+s.view.candidate_id.slice(0,16)+' · '+(s.view.outcome||'published phishing-labelled sample'):'Published labels are separate from current page status.'}catch(e){byId('vmstate').textContent='Waiting for status'}}update();setInterval(update,2000);</script></html>'''


HTML = HTML.replace('<section><h2>VM and verification status</h2>', '''<section><h2>Signals from this visit</h2><dl>
<dt>HTTP status</dt><dd id="http">Pending</dd><dt>Network events</dt><dd id="network">Pending</dd>
<dt>DNS records</dt><dd id="dns">Pending</dd><dt>TLS certificate</dt><dd id="tls">Pending</dd>
<dt>Page structure</dt><dd id="dom">Pending</dd><dt>Scripts</dt><dd id="scripts">Pending</dd></dl>
<h2>Recent traffic</h2><small>Real collector events · origins shown · paths and queries redacted</small>
<div style="overflow-x:auto"><table style="width:100%;text-align:left;border-collapse:collapse"><thead><tr><th>Event</th><th>Method / type</th><th>Status</th><th>Origin</th></tr></thead><tbody id="traffic"></tbody></table></div></section>
<section><h2>VM and verification status</h2>''')
HTML = HTML.replace("const byId=id=>document.getElementById(id);", '''const byId=id=>document.getElementById(id);
function renderSignals(v){byId('http').textContent=v.http_status??'Pending';byId('network').textContent=v.requests===undefined?'Pending':v.requests+' requests · '+v.responses+' responses · '+v.failed+' failed · '+Number(v.transfer_bytes||0).toLocaleString()+' bytes';byId('dns').textContent=v.dns?(v.dns.measured?Object.entries(v.dns.records||{}).map(([k,r])=>k+': '+r.count).join(' · '):(v.dns.missing_reason||v.dns.reason||'Unavailable')):'Pending';byId('tls').textContent=v.tls?(v.tls.measured?(v.tls.protocol+' · '+v.tls.validation):(v.tls.missing_reason||v.tls.reason||'Unavailable')):'Pending';byId('dom').textContent=v.dom?.measured?v.dom.node_count+' nodes · '+v.dom.form_count+' forms · '+v.dom.password_input_count+' password inputs':'Pending';byId('scripts').textContent=v.javascript?.measured?v.javascript.script_count+' scripts · '+v.javascript.page_error_count+' errors':'Pending';byId('traffic').replaceChildren();for(const e of v.traffic||[]){const tr=document.createElement('tr');for(const value of [e.kind,[e.method,e.resource_type].filter(Boolean).join(' '),e.status??e.reason??'',e.url?.origin||'—']){const td=document.createElement('td');td.textContent=String(value);td.style.padding='6px 4px';tr.append(td)}byId('traffic').append(tr)}}''')
HTML = HTML.replace("let n=s.counts", "renderSignals(s.view?.signals||{});let n=s.counts")
HTML = HTML.replace("if(s.frame_present){", "if(s.frame_present&&s.view?.candidate_id===s.view?.frame_candidate_id){")
HTML = HTML.replace("byId('empty').hidden=true}", "byId('empty').hidden=true}else{byId('frame').hidden=true;byId('empty').hidden=false}")
HTML = HTML.replace('<section><h2>Signals from this visit</h2>', '<section><h2>Latest usable capture</h2><p id="committed">Waiting for a committed successful capture.</p></section><section><h2>Signals from this visit</h2>')
HTML = HTML.replace("renderSignals(s.view?.signals||{});", "renderSignals(s.view?.signals||{});if(s.last_capture){const c=s.last_capture,g=c.groups;byId('committed').textContent='Endpoint '+c.candidate_id.slice(0,16)+' · HTTP '+g.http.status+' · '+g.dom.node_count+' DOM nodes · '+g.dom.form_count+' forms · '+g.dom.password_input_count+' password inputs · '+g.javascript.script_count+' scripts. Saved '+new Date(c.captured_at).toLocaleTimeString()}")
HTML = HTML.replace("let n=s.counts?.usable_per_class?.phishing||0;", "let n=(s.prior_campaign_counts?.phishing_usable||0)+(s.counts?.usable_per_class?.phishing||0);")
HTML = HTML.replace("(s.counts?.attempts||0)+' / 800'", "((s.prior_campaign_counts?.attempts||0)+(s.counts?.attempts||0))+' / 800'")
HTML = HTML.replace("const byId=id=>document.getElementById(id);", '''const byId=id=>document.getElementById(id);let frameStamp='',frameUrl=null,frameBusy=false;
async function refreshFrame(s){const stamp=s.run_id+':'+s.view?.utc;if(frameBusy||stamp===frameStamp)return;frameBusy=true;try{const r=await fetch('/frame.jpg',{cache:'no-store'});if(!r.ok)return;const b=await r.blob();const old=frameUrl;frameUrl=URL.createObjectURL(b);byId('frame').src=frameUrl;if(old)URL.revokeObjectURL(old);frameStamp=stamp}finally{frameBusy=false}}window.addEventListener('pagehide',()=>{if(frameUrl)URL.revokeObjectURL(frameUrl)});''')
HTML = HTML.replace("byId('frame').src='/frame.jpg?t='+Date.now();", "refreshFrame(s);")
HTML = HTML.replace("if(s.frame_present&&s.view?.candidate_id===s.view?.frame_candidate_id){",
                    "if(s.frame_present&&s.view?.candidate_id&&s.view.candidate_id===s.view.frame_candidate_id){")


def operator_html():
    """Use run-specific counters; never display the old completion quota."""
    page = HTML.replace('Additional usable phishing captures', 'Usable captures this run')
    page = page.replace('New campaign attempts', 'Attempts including retries')
    page = page.replace('Balanced professor target', 'Captures by published class')
    page = page.replace('Preparing the separately approved campaign', 'Preparing your operator run')
    page = page.replace('Campaign stopped — ', 'Run ended — ')
    page = page.replace('published phishing-labelled sample', 'historical dataset sample')
    page = page.replace('<h2>Signals from this visit</h2>', '<h2 id="signalheading">Signals from this visit</h2>')
    page = page.replace('<section><h2>Latest usable capture</h2>',
        '<section><h2>Latest completed attempt</h2><p id="lastattempt">Waiting for the first completed visit.</p>'
        '<details><summary>Ubuntu VM startup log</summary><pre id="bootlog" style="white-space:pre-wrap;max-height:240px;overflow:auto">Waiting for boot.</pre></details></section>'
        '<section><h2>Dataset attempts</h2><p id="target">Waiting for the dataset queue.</p>'
        '<div style="overflow:auto"><table style="width:100%;text-align:left"><thead><tr><th>Website origin</th><th>Published label</th><th>Outcome</th><th>Reason</th></tr></thead><tbody id="history"></tbody></table></div></section>'
        '<section><h2>Latest usable capture</h2>')
    script = """function renderOperator(s){
const c=s.counts||{}, cap=s.operator?.max_attempts||0, n=Number(c.attempts||0);
const u=c.usable_per_class||{};
byId('captures').textContent=Number(u.legitimate||0)+Number(u.phishing||0);
byId('attempts').textContent=n+' / '+cap;
byId('balanced').textContent=(u.legitimate||0)+' legitimate / '+(u.phishing||0)+' phishing';
byId('progress').max=cap||1;byId('progress').value=n;
byId('bootlog').textContent=s.boot?.text||'Waiting for Ubuntu startup.';
const history=s.history||[];byId('history').replaceChildren();
for(const a of [...history].reverse()){const tr=document.createElement('tr');for(const v of [a.origin,a.label,a.outcome||'Checking DNS / loading',a.reason||'']){const td=document.createElement('td');td.textContent=String(v);td.style.padding='6px';tr.append(td)}byId('history').append(tr)}
byId('target').textContent=s.view?.origin?('Current dataset endpoint: '+s.view.origin+' · '+(s.view.label||'historical label')):('Every dataset attempt is saved, including DNS failures and unavailable pages.');
byId('empty').textContent=s.finished?'This run has ended. No website is being visited.':'Waiting for a browser image from the current visit.';
if(!s.finished&&s.view?.reason==='dns_unavailable'){byId('empty').textContent='DNS lookup failed for this dataset endpoint. No page could open. The failed outcome is saved and the queue continues.'}
byId('signalheading').textContent=s.finished?'Saved signals from the latest usable capture':'Signals from this visit';
if(s.finished&&s.last_capture){const g=s.last_capture.groups;renderSignals({http_status:g.http.status,requests:g.network.request_count,responses:g.network.response_count,failed:g.network.failed_request_count,transfer_bytes:g.network.response_transfer_bytes,dns:g.dns,tls:g.tls,dom:g.dom,javascript:g.javascript})}
const latest=[...history].reverse().find(a=>a.finished)||s.last_attempt;
if(latest){const a=latest;byId('lastattempt').textContent=(a.origin||a.candidate_id.slice(0,16))+' · '+a.label+' · '+a.outcome+(a.reason?' · '+a.reason:'')+' · '+new Date(a.finished*1000).toLocaleTimeString()}
}
"""
    page = page.replace('<script>', '<script>' + script, 1)
    page = page.replace("byId('vmstate').textContent=s.vm_running?", "renderOperator(s);byId('vmstate').textContent=s.vm_running?")
    return page


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--operator',action='store_true')
    args=parser.parse_args();root=args.directory.resolve()
    workspace=Path(__file__).resolve().parents[1]
    assert root.is_relative_to(workspace/'tmp') and root.is_dir()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path=self.path.split('?',1)[0]
            if path=='/':data,kind=(operator_html() if args.operator else HTML).encode(),'text/html; charset=utf-8'
            elif path=='/state.json':
                p=root/'status.json'
                if p.exists() and not p.is_symlink() and p.stat().st_size<65536:
                    try:
                        value=json.loads(p.read_bytes())
                        if args.operator:
                            for filename,key in (('operator.json','operator'),('boot.json','boot'),('last-attempt.json','last_attempt')):
                                extra=root/filename
                                if extra.is_file() and not extra.is_symlink() and extra.stat().st_size<65536:
                                    value[key]=json.loads(extra.read_text(encoding='utf-8'))
                        completed=root/'last-capture.json'
                        if completed.is_file() and not completed.is_symlink() and completed.stat().st_size<100000:
                            value['last_capture']=json.loads(completed.read_text())
                        observer=root/'observer.json'
                        if observer.is_file() and not observer.is_symlink() and observer.stat().st_size<65536:
                            observed=json.loads(observer.read_text())
                            if observed.get('source_run_id')==value.get('run_id'):
                                value['view']=observed
                                value['frame_present']=(root/'observer.jpg').is_file()
                        data=json.dumps(value).encode()
                    except (OSError,ValueError):data=b'{}'
                else:data=b'{}'
                kind='application/json'
            elif path=='/frame.jpg':
                p=root/('observer.jpg' if (root/'observer.jpg').is_file() else 'latest.jpg')
                if not p.is_file() or p.is_symlink() or p.stat().st_size>524288:
                    self.send_error(404);return
                data,kind=p.read_bytes(),'image/jpeg'
            else:self.send_error(404);return
            self.send_response(200);self.send_header('Content-Type',kind)
            self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',"default-src 'none'; img-src 'self' blob:; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers();self.wfile.write(data)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    print('View-only monitor: http://127.0.0.1:'+str(args.port),flush=True)
    try:server.serve_forever()
    finally:server.server_close()


if __name__=='__main__':main()
