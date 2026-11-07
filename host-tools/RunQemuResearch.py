"""Supervise a separate QEMU/WHPX VM through verification and an optional guarded pilot.

No Windows installation, boot, protection, power-schedule or application changes.
The original VirtualBox VM is never started. All guest writes use a new overlay.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import shutil
import subprocess
import sys
import tarfile
import time
import shlex

from ResearchPaths import host_configuration, ssh_configuration

ROOT = Path(__file__).resolve().parents[1]
APP = '/opt/phishing-study-public-20261026-05/app'
PY = '/opt/phishing-study-fixtures/venv/bin/python'
DATA = '/var/lib/phishing-study-public'
SOURCE = '8a9fe608d66387a51429251e62f89178468dc7378fba342dfc4f6d9084d233a5'
RUNTIME = ROOT / '.local-vm/qemu-review-20261031-01/extracted'
BASE = ROOT / '.local-vm/qemu-trial-20261031-01/current-disk-flat.raw'
BASE_HASH = '7b412bec4c52a324ac5cc787624e11e8f3c4d3fa2967adb3f409996cb5bb0aa2'

def utc(): return datetime.now(timezone.utc).isoformat()

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def available_ram():
    class Status(ctypes.Structure):
        _fields_ = [('length',ctypes.c_ulong),('load',ctypes.c_ulong)] + [(n,ctypes.c_ulonglong) for n in
            ('total_phys','avail_phys','total_page','avail_page','total_virtual','avail_virtual','extended')]
    status=Status(); status.length=ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)): raise OSError('Memory status unavailable')
    return status.avail_phys / 2**30


def reconcile_counts(guest):
    keys = ('attempts', 'distinct_urls_attempted', 'failed_attempts', 'unfinished_attempts',
            'usable_per_class', 'collector_stop_reason')
    final = guest.get('pilot_report')
    if isinstance(final, dict) and all(key in final for key in keys):
        return {key: final[key] for key in keys}
    return guest['pilot_counts']

class Run:
    def __init__(self, args):
        global APP, SOURCE
        assert re.fullmatch(r'/opt/[A-Za-z0-9_/-]+/app', args.app_root)
        assert re.fullmatch(r'[a-f0-9]{64}', args.expected_source_hash)
        assert 406 <= args.expected_tests <= 1000
        completion_path = getattr(args, 'completion', None)
        self.completion = None
        if completion_path is not None:
            sys.path.insert(0, str(ROOT / 'phishing-study'))
            from study.phiusiil_completion import validate_completion
            self.completion = validate_completion(json.loads(completion_path.read_text()))
            self.completion_intake = getattr(args, 'completion_intake', None)
            assert self.completion_intake is not None
            intake_manifest=json.loads((self.completion_intake/'intake-manifest.json').read_text())
            assert intake_manifest['completion']==self.completion and len(intake_manifest['selected'])==800
            assert sha(self.completion_intake/'candidates.csv')==intake_manifest['csv_sha256']
            self.completion_intake_hash=sha(self.completion_intake/'intake-manifest.json')
        limit = 800 if self.completion else 400
        assert type(args.max_attempts) is int and 1 <= args.max_attempts <= limit
        if self.completion:
            from study.campaign_continuation import remaining_phishing_target
            prior=json.loads(args.continuation.read_text()) if args.continuation else None
            assert type(args.usable_per_class) is int and args.usable_per_class==remaining_phishing_target(prior,args.max_attempts)
        else:
            assert type(args.usable_per_class) is int and args.usable_per_class in (50,75)
        APP, SOURCE = args.app_root, args.expected_source_hash
        self.args=args; self.output=args.output.resolve()
        assert self.output.is_relative_to(ROOT) and not self.output.exists(), 'Fresh workspace evidence output required'
        assert 10 <= args.minutes <= (130 if self.completion else 60)
        self.output.mkdir(parents=True)
        self.run_id=args.run_id
        assert self.run_id.replace('-','').isalnum() and len(self.run_id)<45
        self.assessment=f'{DATA}/assessment-{self.run_id}'
        self.pilot=f'{DATA}/pilot-{self.run_id}'
        self.private=f'{DATA}/pilot-private-{self.run_id}'
        self.dns=f'{DATA}/pilot-dns-{self.run_id}'
        self.rootunit='study-public-assessment-'+self.run_id
        self.pilotunit='study-public-supervised-'+self.run_id
        self.started=time.monotonic(); self.hard_end=self.started+args.minutes*60
        self.work_end=self.hard_end-300
        if args.campaign_budget:
            budget=json.loads(args.campaign_budget.read_text(encoding='utf-8-sig'))
            assert args.max_attempts<=budget['remaining_attempts']
            assert budget['attempts_used']+args.max_attempts<=budget['attempt_limit']<=limit
            remaining=datetime.fromisoformat(budget['collection_deadline_utc']).timestamp()-time.time()
            assert remaining>600, 'Insufficient time left in the original collection window'
            self.work_end=min(self.work_end,self.started+remaining)
            self.save_budget=budget
        else:self.save_budget=None
        self.vm=None; self.first_clock=None; self.clock_failures=[]; self.samples=0; self.nonce=None
        self.result={'started_utc':utc(),'source_hash':SOURCE,'status':'failed','collection_activation':False,
            'pilot_requested':args.pilot,'run_id':self.run_id,'vm_memory_mib':4096,'vm_cpus':2,
            'maximum_host_minutes':args.minutes,'no_windows_settings_changed':True,'original_vm_started':False}
        self.result.update(expected_tests=args.expected_tests,maximum_new_attempts=args.max_attempts,
                           target_per_published_class=args.usable_per_class,campaign_budget=self.save_budget)
        if getattr(args, 'dataset_observation', False):
            self.result.update(verification_profile='local-dataset-observation-v1',
                verification_scope='local kernel, Chromium, logging and bounded lifecycle controls',
                owned_site_test_performed=False, network_isolation_verified=False,
                public_dns_verified=False, public_tls_verified=False)
        self.result['completion'] = self.completion
        self.live_directory = getattr(args, 'live_view_dir', None)
        if self.live_directory:
            self.live_directory = self.live_directory.resolve()
            assert self.live_directory.is_relative_to(ROOT / 'tmp')
            self.live_directory.mkdir(parents=True, exist_ok=True)
        self.config=self.output/'ssh_config'
        self.ssh=['ssh','-F',str(self.config),'-o','ConnectTimeout=3','-o','ServerAliveInterval=3','-o','ServerAliveCountMax=2','study-vm']

    def save(self,name,value):
        path=self.output/name; temp=path.with_name(path.name+'.tmp')
        with temp.open('w',encoding='utf-8') as stream:
            json.dump(value,stream,indent=2);stream.flush();os.fsync(stream.fileno())
        # Windows readers may briefly deny delete sharing during a progress read.
        # Keep atomic replacement and a finite retry; never discard the receipt.
        for attempt in range(20):
            try:
                temp.replace(path)
                break
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(.05)

    def remote(self,code,timeout=20,python=True):
        command=("sudo -n "+PY+" - <<'PY'\n"+code+"\nPY") if python else code
        run=subprocess.run([*self.ssh,command],capture_output=True,text=True,timeout=timeout)
        if run.returncode: raise RuntimeError('SSH command failed: '+run.stderr[-1200:]+run.stdout[-1200:])
        return run.stdout

    def start(self):
        assert available_ram() >= 5, '5 GiB available RAM buffer required before a 4 GiB test VM'
        assert shutil.disk_usage(ROOT).free >= 50*2**30, '50 GiB host working-space buffer required'
        self.host = host_configuration(ROOT)
        self.region = self.host['region']
        self.result['region'] = self.region
        original_vm = self.host.get('original_virtualbox')
        if original_vm:
            state=subprocess.check_output([original_vm['executable'],'showvminfo',
                original_vm['uuid'],'--machinereadable'],text=True)
            assert 'VMState="poweroff"' in state.splitlines(), 'Original VM must stay powered off'
        for port in (22243,44443):
            with socket.socket() as sock:sock.bind(('127.0.0.1',port))
        runtime, base = Path(self.host['qemu_directory']), Path(self.host['base_disk'])
        assert sha(base)==self.host['base_sha256'], 'Prepared base disk changed; preserve it and rerun setup'
        known=self.output/'known_hosts'
        known.write_text(Path(self.host['known_hosts_file']).read_text().replace('[127.0.0.1]:22240','[127.0.0.1]:22243'))
        self.config.write_text(ssh_configuration(self.host, known))
        overlay=self.output/'vm-overlay.qcow2'
        creation=subprocess.run([str(runtime/'qemu-img.exe'),'create','-f','qcow2','-F',self.host['base_format'],'-b',str(base),str(overlay)],capture_output=True,text=True,timeout=20)
        self.save('overlay-create.json',{'code':creation.returncode,'stdout':creation.stdout,'stderr':creation.stderr})
        assert creation.returncode==0
        argv=[str(runtime/'qemu-system-x86_64.exe'),'-no-user-config','-nodefaults','-machine','pc','-accel','whpx','-cpu','host',
            '-smp','2,sockets=1,cores=2,threads=1','-m','4096','-L',str(runtime/'share'),'-display','none','-vga','none','-monitor','none',
            '-qmp','tcp:127.0.0.1:44443,server=on,wait=off','-serial','file:'+str(self.output/'serial.log'),'-rtc','base=utc,clock=host',
            '-no-reboot','-boot','order=c,strict=on','-drive','file='+str(overlay)+',format=qcow2,if=ide,index=0',
            '-netdev','user,id=net0,hostfwd=tcp:127.0.0.1:22243-:22','-device','e1000,netdev=net0,mac=08:00:27:0a:d2:be,addr=0x3']
        with (self.output/'qemu-console.txt').open('xb') as stream:
            self.vm=subprocess.Popen(argv,stdout=stream,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
        self.save('vm-launch.json',{'utc':utc(),'argv':argv,'pid':self.vm.pid,'qemu_executable_sha256':sha(runtime/'qemu-system-x86_64.exe'),
            'supervisor_sha256':sha(__file__),'base_sha256_receipt':self.host['base_sha256'],'base_hash_measured_before_boot':True,'no_fallback_accelerator':True,'shared_host_devices':False})
        end=min(self.work_end,time.monotonic()+150)
        while time.monotonic()<end:
            if self.vm.poll() is not None:raise RuntimeError('VM exited before SSH readiness')
            try:
                self.remote('true',timeout=5,python=False)
                return
            except (RuntimeError,subprocess.TimeoutExpired):time.sleep(2)
        raise TimeoutError('VM boot deadline')

    def preflight(self):
        code=f'''import json,pathlib,subprocess,sys,time,shutil,hashlib,importlib.metadata
sys.path.insert(0,{APP!r})
from study.deployment import source_hash
r={{'epoch':time.time(),'source_hash':source_hash({APP!r}),'hostname':subprocess.check_output(['hostname'],text=True,timeout=3).strip(),'clocksource':pathlib.Path('/sys/devices/system/clocksource/clocksource0/current_clocksource').read_text().strip(),'free_disk':shutil.disk_usage({DATA!r}).free,'nft':subprocess.check_output(['nft','list','ruleset'],text=True,timeout=5),'active':subprocess.check_output(['systemctl','list-units','--state=active','--no-legend','study-public-*'],text=True,timeout=5),'accounts_idle':all(subprocess.run(['pgrep','-u',u],capture_output=True,timeout=3).returncode==1 for u in ('study-public','study-public-dns')),'numpy':importlib.metadata.version('numpy'),'cpu_flags':next(l for l in pathlib.Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('flags')),'packages':'\\n'.join(sorted(d.metadata['Name']+'=='+d.version for d in importlib.metadata.distributions()))}}
assert r['source_hash']=={SOURCE!r} and r['hostname']=='phishing-study-ubuntu' and r['accounts_idle'] and not r['nft'].strip() and not r['active'].strip() and r['free_disk']>15000000000
assert r['clocksource']=='hyperv_clocksource_tsc_page'
print(json.dumps(r))'''
        report=json.loads(self.remote(code,timeout=30));self.save('guest-preflight.json',report)

    def install_source(self):
        if self.args.source_archive is None:
            return
        assert self.args.source_manifest is not None
        manifest=json.loads(self.args.source_manifest.read_text())
        assert manifest['source_hash']==SOURCE and sha(self.args.source_archive)==manifest['archive_sha256']
        remote_archive='/var/tmp/source-'+self.run_id+'.tar.gz'
        subprocess.run(['scp','-F',str(self.config),str(self.args.source_archive),'study-vm:'+remote_archive],check=True,timeout=30)
        code=f'''import hashlib,json,pathlib,tarfile,sys,unittest,os
p=pathlib.Path({remote_archive!r});assert hashlib.sha256(p.read_bytes()).hexdigest()=={manifest['archive_sha256']!r}
base=pathlib.Path({APP!r}).parent;assert not base.exists();base.mkdir(mode=0o755)
with tarfile.open(p,'r:gz') as archive:
 for m in archive.getmembers():
  n=pathlib.PurePosixPath(m.name)
  assert n.parts[0]=='app' and not n.is_absolute() and '..' not in n.parts and all(':' not in a and '\\\\' not in a for a in n.parts) and (m.isfile() or m.isdir())
 archive.extractall(base,filter='data')
for f in base.rglob('*'):
 os.chown(f,0,0);f.chmod(0o755 if f.is_dir() or f.suffix=='.sh' else 0o644)
sys.path.insert(0,{APP!r})
from study.deployment import source_hash,source_files
assert source_hash({APP!r})=={SOURCE!r}
count=unittest.defaultTestLoader.discover({(APP+'/tests')!r}).countTestCases()
assert count=={self.args.expected_tests!r},count
print(json.dumps({{'installed_source_hash':source_hash({APP!r}),'source_files':len(source_files({APP!r})),'discovered_tests':count,'root':{APP!r}}}))'''
        self.save('source-install.json',json.loads(self.remote(code,timeout=45)))

    def launch_verification(self):
        continuation_option=''
        if self.completion:
            path=DATA+'/completion-'+self.run_id+'.json'
            code=f'import pathlib,os\np=pathlib.Path({path!r});assert not p.exists();p.write_text({json.dumps(self.completion)!r});os.chown(p,0,0);p.chmod(0o444)'
            self.remote(code)
            continuation_option += ' --completion '+path
            self.save('completion-input.json',self.completion)
            protected=DATA+'/completion-intake-'+self.run_id
            entries=[]
            for name in ('candidates.csv','intake-manifest.json'):
                source=self.completion_intake/name
                temporary='/var/tmp/completion-'+self.run_id+'-'+name
                subprocess.run(['scp','-F',str(self.config),str(source),'study-vm:'+temporary],check=True,timeout=30)
                entries.append((name,temporary,sha(source)))
            code=f'''import pathlib,hashlib,shutil,os
d=pathlib.Path({protected!r});assert not d.exists();d.mkdir(mode=0o755)
for name,source,expected in {entries!r}:
 p=pathlib.Path(source);assert p.is_file() and not p.is_symlink() and p.stat().st_size<8000000
 data=p.read_bytes();assert hashlib.sha256(data).hexdigest()==expected
 t=d/name;t.write_bytes(data);os.chown(t,0,0);t.chmod(0o444)
'''
            self.remote(code)
            continuation_option += ' --completion-intake '+protected
            self.save('completion-intake-transfer.json',{'manifest_sha256':self.completion_intake_hash,'files':entries,'root_protected_path':protected})
        if self.args.continuation:
            value=json.loads(self.args.continuation.read_text(encoding='utf-8-sig'))
            path=DATA+'/continuation-'+self.run_id+'.json'
            code=f'import pathlib,os\np=pathlib.Path({path!r});assert not p.exists();p.write_text({json.dumps(value)!r});os.chown(p,0,0);p.chmod(0o444)'
            self.remote(code)
            continuation_option+=' --continuation '+path
            self.save('continuation-input.json',value)
        command=f'sudo -n systemd-run --unit={self.rootunit} --property=RuntimeMaxSec=1200 --property=TimeoutStopSec=90 --property=MemoryMax=1G --property=MemorySwapMax=0 --property=CPUQuota=200% --property=TasksMax=128 --property=KillMode=control-group --setenv=PYTHONPATH={APP} --setenv=PYTHONDONTWRITEBYTECODE=1 {PY} -m study.public_assessment --output {self.assessment} --source-csv /var/lib/phishing-study-public-originals-20261026-01/source.csv --membership /var/lib/phishing-study-public-originals-20261026-01/split-membership.csv --audit /var/lib/phishing-study-public-originals-20261026-01/audit.json --max-attempts {self.args.max_attempts} --usable-per-class {self.args.usable_per_class}'
        command+=continuation_option
        command+=' --region '+shlex.quote(self.region)
        if self.live_directory:
            command+=' --live-view'
        if getattr(self.args, 'dataset_observation', False):
            command+=' --dataset-observation'
        output=self.remote(command,python=False);self.save('verification-launch.json',{'utc':utc(),'command':command,'stdout':output,'automatic_pilot_in_assessment':False})

    def settle_boot_clock(self):
        # Ubuntu may synchronise wall time shortly after SSH starts. Record that
        # preparation separately; never reset the baseline after testing starts.
        samples=[];stable=0;previous=None;deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            before=time.time()
            sample=json.loads(self.remote("import json,time,subprocess;print(json.dumps({'epoch':time.time(),'monotonic':time.monotonic(),'ntp_synchronised':subprocess.check_output(['timedatectl','show','--property=NTPSynchronized','--value'],text=True).strip()}))"))
            after=time.time();offset=sample['epoch']-(before+after)/2
            samples.append({'utc':utc(),**sample,'host_offset_seconds':offset,'roundtrip_seconds':after-before})
            stable=stable+1 if previous is not None and abs(offset-previous)<.5 and sample['monotonic']>=35 else 0
            previous=offset
            if stable>=3:
                self.save('boot-clock-settle.json',{'passed':True,'samples':samples,'collection_started':False,
                    'later_drift_threshold_unchanged_seconds':2,'baseline_reset_during_verification':False})
                return
            time.sleep(2)
        self.save('boot-clock-settle.json',{'passed':False,'samples':samples,'collection_started':False})
        raise RuntimeError('Boot clock did not settle before the fixed preparation deadline')

    def probe(self,enforce=True):
        code=f'''import pathlib,json,subprocess,sys,time
sys.path.insert(0,{APP!r})
from study.public_pilot import summarize_dataset
p=pathlib.Path({self.assessment!r});r={{'epoch':time.time(),'monotonic':time.monotonic(),'clocksource':pathlib.Path('/sys/devices/system/clocksource/clocksource0/current_clocksource').read_text().strip(),'reports':{{}}}}
for n,f in [('assessment','assessment-result.json'),('suite','suite/test-report.json'),('selftest','selftest/fixture-report.json'),('kernel','kernel/kernel-report.json'),('lifecycle','kernel/lifecycle-trials.json'),('connected','connected/connected-report.json')]:
 q=p/f
 if q.exists():r['reports'][n]=json.loads(q.read_text())
f=p/'suite/tests.txt'
if f.exists():r['test_tail']=f.read_text(errors='replace').splitlines()[-3:]
f=pathlib.Path({self.pilot!r})/'pilot-report.json'
if f.exists():r['pilot_report']=json.loads(f.read_text())
r['pilot_counts']=summarize_dataset(pathlib.Path({self.private!r})/'dataset')
r['dataset_attempts']=[]
db=pathlib.Path({self.private!r})/'dataset/study.sqlite'
if not db.is_file():db=pathlib.Path({self.pilot!r})/'dataset/study.sqlite'
if db.is_file():
 import sqlite3
 from urllib.parse import urlsplit
 with sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True,timeout=.5) as connection:
  connection.row_factory=sqlite3.Row
  for row in connection.execute('SELECT a.id,a.candidate_id,a.started,a.finished,a.outcome,a.artifact,c.label,c.url FROM attempts a JOIN candidates c ON c.id=a.candidate_id ORDER BY a.started LIMIT 400'):
   item=dict(row);url=urlsplit(item.pop('url'));item['origin']=url.scheme+'://'+url.netloc
   artifact=item.pop('artifact');q=db.parent/artifact if artifact else None
   if q and q.is_file() and not q.is_symlink() and q.resolve().is_relative_to(db.parent.resolve()) and q.stat().st_size<2000000:
    saved=json.loads(q.read_text());item['reason']=saved.get('policy_reason') or saved.get('error_type') or saved.get('groups',{{}}).get('http',{{}}).get('status')
   r['dataset_attempts'].append(item)
r['vm']={{'uptime':pathlib.Path('/proc/uptime').read_text().split()[0],'loadavg':pathlib.Path('/proc/loadavg').read_text().strip(),'memory_available_kib':next(l.split()[1] for l in pathlib.Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:'))}}
if {bool(getattr(self,'live_directory',None))!r}:
 import base64
 v=pathlib.Path({self.private!r})/'live-view';s=v/'status.json';f=v/'latest.jpg'
 if s.exists() and not s.is_symlink() and s.stat().st_size<4096:r['live_view']=json.loads(s.read_text())
 if f.exists() and not f.is_symlink() and 0<f.stat().st_size<=524288:r['live_frame_base64']=base64.b64encode(f.read_bytes()).decode()
r['active_units']=subprocess.check_output(['systemctl','list-units','--state=active','--no-legend','--plain','study-public-*'],text=True)
d=subprocess.check_output(['dmesg','--time-format','iso'],text=True).splitlines()
r['timing_warnings']=[l for l in d if 'soft lockup' in l or ('clocksource' in l and 'unstable' in l) or 'rcu: INFO:' in l or 'Watchdog detected hard LOCKUP' in l]
print(json.dumps(r))'''
        before=time.time();mono=time.monotonic()
        for attempt in range(2):
            try:
                guest=json.loads(self.remote(code,timeout=12))
                break
            except (RuntimeError,subprocess.TimeoutExpired):
                if attempt:raise
                with (self.output/'transport-retries.jsonl').open('a') as stream:
                    stream.write(json.dumps({'utc':utc(),'action':'one_bounded_read_only_probe_retry'})+'\n')
                time.sleep(.1)
        after=time.time()
        # The root controller moves the private dataset into its frozen output.
        # Once its final receipt exists, use those actual counts rather than
        # briefly displaying zeros from the now-empty private directory.
        guest['pilot_counts'] = reconcile_counts(guest)
        frame = guest.pop('live_frame_base64', None)
        if self.live_directory:
            try:
                import base64
                if frame:
                    data = base64.b64decode(frame,validate=True)
                    if len(data)<=524288 and data.startswith(b'\xff\xd8'):
                        p=self.live_directory/'latest.jpg';t=p.with_suffix('.tmp');t.write_bytes(data);os.replace(t,p)
                state={'utc':utc(),'vm_running':self.vm is not None and self.vm.poll() is None,
                    'run_id':self.run_id,'counts':guest['pilot_counts'],'vm':guest['vm'],
                    'view':guest.get('live_view'),'verification':{k:v.get('status',v.get('successful')) for k,v in guest['reports'].items() if isinstance(v,dict)},
                    'host_available_ram_gib':available_ram(),'frame_present':(self.live_directory/'latest.jpg').exists(),
                    'history':guest.get('dataset_attempts',[])[-25:]}
                if self.completion and self.args.continuation:
                    prior=json.loads(self.args.continuation.read_text())
                    state['prior_campaign_counts']={'attempts':prior['attempts_used'],'phishing_usable':prior['usable_phishing']}
                p=self.live_directory/'status.json';t=p.with_suffix('.tmp');t.write_text(json.dumps(state));os.replace(t,p)
            except (OSError,ValueError):
                pass
        elapsed=time.monotonic()-mono;offset=guest['epoch']-(before+after)/2
        if self.first_clock is None:self.first_clock=(mono,guest['monotonic'],offset)
        drift=(guest['monotonic']-self.first_clock[1])-(mono-self.first_clock[0])
        record={'utc':utc(),'roundtrip_seconds':elapsed,'offset_seconds':offset,'elapsed_drift_seconds':drift,'host_available_ram_gib':available_ram(),'guest':guest}
        failures=[]
        if elapsed>5:failures.append('response_over_5_seconds')
        if abs(drift)>2 or abs(offset-self.first_clock[2])>2:failures.append('clock_drift_over_2_seconds')
        if guest['clocksource']!='hyperv_clocksource_tsc_page' or guest['timing_warnings']:failures.append('guest_clock_health_failure')
        if record['host_available_ram_gib']<1.5:failures.append('host_ram_below_1_5_gib')
        record['failures']=failures;self.samples+=1;self.clock_failures.extend(failures)
        with (self.output/'timing.jsonl').open('a') as stream:
            stream.write(json.dumps(record)+'\n');stream.flush();os.fsync(stream.fileno())
        self.save('progress.json',record)
        if failures and enforce:raise RuntimeError('Host timing/resource health failed: '+','.join(failures))
        return guest

    def launch_pilot(self, guest):
        assessment=guest['reports']['assessment'];suite=guest['reports']['suite']
        observation = getattr(self.args, 'dataset_observation', False)
        assert assessment['status']=='passed'
        assert assessment.get('observation_allowed') is True if observation else assessment['network_isolation_verified'] is True
        assert suite['successful'] and suite['tests_run']==self.args.expected_tests and suite['passed']==self.args.expected_tests
        browsers=suite['browser_tests']
        assert browsers['passed']>=18 and browsers['passed']==browsers['discovered']==browsers['executed'] and not browsers['missing']
        assert self.samples>=3 and not self.clock_failures and time.monotonic()<self.work_end-180
        code=f'''import json,pathlib,sys
sys.path.insert(0,{APP!r})
from study.public_web import validate_public_bundle,validate_execution_evidence,validate_public_evidence_files
bundle=pathlib.Path({self.assessment!r})/'bundle';manifest=validate_public_bundle(bundle,root={APP!r})
evidence=json.loads((pathlib.Path({self.assessment!r})/'deployment-evidence.json').read_text())
validate_execution_evidence(manifest,evidence);validate_public_evidence_files(evidence)
assert manifest.get('usable_per_class',50)=={self.args.usable_per_class}
assert manifest.get('completion')=={self.completion!r}
assert not {bool(self.completion)!r} or manifest['intake_manifest_hash']=={getattr(self,'completion_intake_hash',None)!r}
print(json.dumps({{'nonce':evidence['nonce'],'source_hash':manifest['source_hash'],'verification_profile':manifest['verification_profile'],'usable_per_class':manifest.get('usable_per_class',50)}}))'''
        gate=json.loads(self.remote(code));assert gate['source_hash']==SOURCE and gate['verification_profile']==('local-dataset-observation-v1' if observation else 'local-public-web-v1')
        self.nonce=gate['nonce'];self.save('host-activation-review.json',{'utc':utc(),'gate':gate,'host_clock_samples':self.samples,'clock_failures':self.clock_failures,'earlier_shutdown_deadline':True,'source_unchanged':True})
        if self.completion and self.save_budget is None:
            start=time.time()
            self.work_end=min(self.work_end,time.monotonic()+7200)
            self.save_budget={'campaign_id':self.completion['campaign_id'],'started_utc':utc(),
                'collection_deadline_utc':datetime.fromtimestamp(start+7200,timezone.utc).isoformat(),
                'attempt_limit':800,'attempts_used':0,'remaining_attempts':800,'target_phishing_usable':59}
            self.result['campaign_budget']=self.save_budget
            self.save('campaign-collection-window.json',self.save_budget)
        script=f'''import json,pathlib,pwd,sys
sys.path.insert(0,{APP!r})
from study.public_assessment import leaf
from study.public_pilot import run_pilot
p=pathlib.Path({self.assessment!r})
r=run_pilot(p/'bundle',p/'deployment-evidence.json',p/'intake',pathlib.Path({self.pilot!r}),leaf(pathlib.Path({self.private!r}),pwd.getpwnam('study-public').pw_uid),leaf(pathlib.Path({self.dns!r}),pwd.getpwnam('study-public-dns').pw_uid),pathlib.Path({(DATA+'/pilot-phase-'+self.run_id+'.txt')!r}),{self.nonce!r})
print(json.dumps(r,indent=2))
raise SystemExit(0 if r['status']=='passed' else 1)
'''
        self.save('pilot-entry-script.json',{'sha256':hashlib.sha256(script.encode()).hexdigest(),'script':script,'uses_existing_root_gate_and_run_pilot':True})
        path=f'{DATA}/supervised-pilot-{self.run_id}.py'
        write=f'import pathlib\np=pathlib.Path({path!r});assert not p.exists();p.write_text({script!r});p.chmod(0o600)'
        self.remote(write)
        command=f'sudo -n systemd-run --unit={self.pilotunit} --property=RuntimeMaxSec={max(180,int(self.work_end-time.monotonic())+60)} --property=TimeoutStopSec=90 --property=MemoryMax=1G --property=MemorySwapMax=0 --property=CPUQuota=200% --property=TasksMax=128 --setenv=PYTHONPATH={APP} --setenv=PYTHONDONTWRITEBYTECODE=1 {PY} {path}'
        self.remote(command,python=False);self.result['pilot_controller_launched']=True
        self.result['collection_activation']=None # Await the actual worker receipt; launching a controller is not activation.

    def stop_work(self):
        code=f'''import json,subprocess,time
units=subprocess.check_output(['systemctl','list-units','--type=service','--state=running','--plain','--no-legend','study-public-*'],text=True).splitlines()
names=[l.split()[0] for l in units]
children=[u for u in names if u not in {{{(self.rootunit+'.service')!r},{(self.pilotunit+'.service')!r}}} and 'pilot-dns' not in u]
if children:subprocess.run(['systemctl','stop','--no-block',*children],check=True,timeout=5)
for u in names:
 if u in {{{(self.rootunit+'.service')!r},{(self.pilotunit+'.service')!r}}}:subprocess.run(['systemctl','kill','--kill-whom=main','--signal=SIGINT',u],capture_output=True,timeout=5)
print(json.dumps({{'units_at_stop':names,'children_stop_requested':children}}))'''
        for attempt in range(3):
            try:
                receipt=json.loads(self.remote(code,timeout=20))
                break
            except RuntimeError as error:
                # Retry only a pre-command connection/banner failure. Repeating
                # a delivered SIGINT could interrupt the controller's cleanup.
                message=str(error).lower()
                if attempt==2 or not any(s in message for s in ('banner','connection refused','connection timed out')):raise
                time.sleep(.2)
        self.save('stop-request.json',{'utc':utc(),'reason':self.result.get('stop_reason'),'receipt':receipt})
        until=time.monotonic()+85
        while time.monotonic()<until:
            try:
                active=self.remote("import subprocess;print(subprocess.check_output(['systemctl','list-units','--state=active','--no-legend','study-public-*'],text=True))").strip()
            except RuntimeError as error:
                if any(s in str(error).lower() for s in ('banner','connection refused','connection timed out')):
                    time.sleep(.2)
                    continue
                raise
            if not active:return
            time.sleep(2)
        raise RuntimeError('Study units did not stop within preserved deadlines')

    def freeze(self):
        code=f'''import pathlib,json,subprocess,sys,shutil,tarfile,datetime
sys.path.insert(0,{APP!r})
from study.deployment import source_hash,source_files,file_hash
out=pathlib.Path({(DATA+'/export-'+self.run_id)!r});assert not out.exists();out.mkdir(mode=0o700)
r={{'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_hash':source_hash({APP!r}),'active_units':subprocess.check_output(['systemctl','list-units','--state=active','--no-legend','study-public-*'],text=True),'accounts_idle':all(subprocess.run(['pgrep','-u',u],capture_output=True).returncode==1 for u in ('study-public','study-public-dns'))}}
for name in ({self.assessment!r},{self.pilot!r},{self.private!r},{self.dns!r},{(DATA+'/verification-private')!r}):
 p=pathlib.Path(name)
 if p.exists():shutil.copytree(p,out/p.name,ignore=shutil.ignore_patterns('live-view'))
app=pathlib.Path({APP!r})
for p in source_files(app):
 t=out/'app'/p.relative_to(app);t.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,t)
for u in ({self.rootunit!r},{self.pilotunit!r}):(out/(u+'.journal.txt')).write_text(subprocess.check_output(['journalctl','-u',u,'--no-pager'],text=True))
(out/'kernel-messages.txt').write_text(subprocess.check_output(['dmesg','--time-format','iso'],text=True))
(out/'final-nft.txt').write_text(subprocess.check_output(['nft','list','ruleset'],text=True))
(out/'freeze-state.json').write_text(json.dumps(r,indent=2))
inventory={{p.relative_to(out).as_posix():{{'bytes':p.stat().st_size,'sha256':file_hash(p)}} for p in sorted(out.rglob('*')) if p.is_file()}}
(out/'inventory.json').write_text(json.dumps(inventory,indent=2))
archive=pathlib.Path({('/var/tmp/evidence-'+self.run_id+'.tar.gz')!r});assert not archive.exists()
with tarfile.open(archive,'w:gz',compresslevel=3) as tar:tar.add(out,arcname='guest')
archive.chmod(0o644)
print(json.dumps({{'archive':str(archive),'sha256':file_hash(archive),'bytes':archive.stat().st_size,'files':len(inventory),'state':r}}))'''
        receipt=json.loads(self.remote(code,timeout=90));self.save('guest-export.json',receipt)
        target=self.output/'guest-evidence.tar.gz'
        subprocess.run(['scp','-F',str(self.config),'study-vm:'+receipt['archive'],str(target)],check=True,timeout=60)
        assert sha(target)==receipt['sha256'];self.result['archive_transfer_hash_verified']=True

    def execute(self):
        try:
            self.start();self.install_source();self.preflight();self.settle_boot_clock();self.probe();self.launch_verification()
            print('Fresh verification running; pilot waits for complete checks and host timing',flush=True)
            stage='verification'
            while time.monotonic()<self.work_end:
                if self.vm.poll() is not None:raise RuntimeError('VM exited unexpectedly')
                guest=self.probe();assessment=guest['reports'].get('assessment')
                if stage=='pilot' and guest.get('pilot_counts',{}).get('attempts',0)>0:
                    self.result['collection_activation']=True
                if stage=='verification' and assessment:
                    if assessment['status']!='passed':raise RuntimeError('Verification failed: '+str(assessment.get('failed')))
                    self.result['verification_passed']=True
                    if self.args.pilot:
                        self.launch_pilot(guest);stage='pilot';print('All verification checks passed; guarded bounded pilot launched',flush=True)
                    else:self.result.update(status='passed',stop_reason='verification_complete_no_pilot_requested');break
                elif stage=='pilot' and guest.get('pilot_report'):
                    self.result.update(status=guest['pilot_report']['status'],pilot=guest['pilot_report'],stop_reason='pilot_controller_finished');break
                time.sleep(5)
            else:self.result['stop_reason']='supervised_host_window_deadline'
        except BaseException as error:
            self.result.update(error_type=type(error).__name__,error=str(error),stop_reason=
                'operator_requested_stop' if str(error)=='operator_requested_stop' else 'verification_or_runtime_failure')
            print('Stopping: '+type(error).__name__+': '+str(error),flush=True)
        finally:
            if self.vm is not None and self.vm.poll() is None:
                try:self.stop_work()
                except BaseException as e:self.result['stop_error']=type(e).__name__+':'+str(e)
                try:
                    final=self.probe(enforce=False);self.save('final-guest-progress.json',final)
                    if final.get('pilot_report'):
                        self.result['pilot']=final['pilot_report'];self.result['collection_activation']=final['pilot_report'].get('collection_activation',False)
                    self.freeze()
                except BaseException as e:self.result['freeze_error']=type(e).__name__+':'+str(e)
                try:
                    self.remote('sudo -n sync\nsudo -n systemctl poweroff --no-block',python=False,timeout=15)
                    self.vm.wait(timeout=45);self.result['graceful_vm_exit']=True
                except BaseException as e:
                    self.result['shutdown_error']=type(e).__name__
                    self.vm.terminate();self.vm.wait(timeout=10);self.result['forced_vm_copy_exit']=True
            self.result.update(finished_utc=utc(),host_duration_seconds=time.monotonic()-self.started,host_timing_samples=self.samples,host_timing_failures=self.clock_failures)
            if any(k in self.result for k in ('stop_error','freeze_error','shutdown_error')):self.result['status']='failed'
            self.save('result.json',self.result)
            if self.live_directory:
                try:
                    path=self.live_directory/'status.json'
                    state=json.loads(path.read_text()) if path.exists() else {}
                    state.update(vm_running=False,finished=True,utc=utc(),stop_reason=self.result['stop_reason'])
                    pilot=self.result.get('pilot',{})
                    if 'attempts' in pilot:
                        state['counts']={key:pilot[key] for key in ('attempts','distinct_urls_attempted','failed_attempts','unfinished_attempts','usable_per_class','collector_stop_reason')}
                    temp=path.with_suffix('.tmp');temp.write_text(json.dumps(state));os.replace(temp,path)
                except (OSError,ValueError):pass
            print(json.dumps({k:v for k,v in self.result.items() if k!='pilot'},indent=2),flush=True)
        return 0 if self.result['status']=='passed' else 1

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--run-id',required=True)
    parser.add_argument('--minutes',type=int,default=45);parser.add_argument('--pilot',action='store_true')
    parser.add_argument('--app-root',default=APP)
    parser.add_argument('--expected-source-hash',default=SOURCE)
    parser.add_argument('--expected-tests',type=int,default=406)
    parser.add_argument('--source-archive',type=Path)
    parser.add_argument('--source-manifest',type=Path)
    parser.add_argument('--max-attempts',type=int,default=400)
    parser.add_argument('--usable-per-class',type=int,default=50)
    parser.add_argument('--campaign-budget',type=Path)
    parser.add_argument('--continuation',type=Path)
    parser.add_argument('--completion',type=Path)
    parser.add_argument('--completion-intake',type=Path)
    parser.add_argument('--live-view-dir',type=Path)
    return Run(parser.parse_args()).execute()

if __name__=='__main__':raise SystemExit(main())
