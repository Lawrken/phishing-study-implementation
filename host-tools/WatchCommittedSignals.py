"""Read only the latest committed usable capture for the local monitor."""
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import subprocess
import time

PY='/opt/phishing-study-fixtures/venv/bin/python'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase',type=Path,required=True);p.add_argument('--directory',type=Path,required=True)
    p.add_argument('--run-id',required=True);a=p.parse_args()
    assert a.run_id.replace('-','').isalnum() and len(a.run_id)<45
    dataset='/var/lib/phishing-study-public/pilot-private-'+a.run_id+'/dataset'
    code=f'''import pathlib,sqlite3,json,hashlib,base64
root=pathlib.Path({dataset!r});dbpath=root/'study.sqlite'
result={{}};view=root.parent/'live-view';status=view/'status.json';frame=view/'latest.jpg'
if status.is_file() and not status.is_symlink() and status.stat().st_size<65536:
 raw=status.read_bytes();state=json.loads(raw)
 if frame.is_file() and not frame.is_symlink() and frame.stat().st_size<=524288:
  image=frame.read_bytes()
  if status.read_bytes()==raw and image.startswith(b'\\xff\\xd8'):
   result['observer']={{'view':state,'frame_base64':base64.b64encode(image).decode()}}
if dbpath.is_file():
 with sqlite3.connect('file:'+str(dbpath)+'?mode=ro',uri=True,timeout=.5) as db:
  db.row_factory=sqlite3.Row
  row=db.execute("SELECT candidate_id,artifact,finished FROM attempts WHERE finished IS NOT NULL AND eligible=1 AND artifact IS NOT NULL ORDER BY finished DESC LIMIT 1").fetchone()
  last=db.execute("SELECT a.candidate_id,a.outcome,a.finished,c.label FROM attempts a JOIN candidates c ON c.id=a.candidate_id WHERE a.finished IS NOT NULL ORDER BY a.finished DESC LIMIT 1").fetchone()
 if last:result['latest_attempt']=dict(last)
 if row:
  path=root/row['artifact'];assert path.resolve().is_relative_to(root.resolve()) and path.is_file() and not path.is_symlink() and path.stat().st_size<2000000
  data=path.read_bytes();record=json.loads(data)
  result['capture']={{'candidate_id':row['candidate_id'],'captured_at':record['captured_at'],'outcome':record['outcome'],'record_sha256':hashlib.sha256(data).hexdigest(),'groups':{{k:record['groups'][k] for k in ('http','dns','tls','dom','javascript','network')}}}}
print(json.dumps(result))'''
    end=time.monotonic()+8000
    errors=0
    while time.monotonic()<end:
        if (a.phase/'result.json').exists():break
        try:
            r=subprocess.run(['ssh','-F',str(a.phase/'ssh_config'),'-o','ConnectTimeout=3',
                'study-vm','sudo -n '+PY+" - <<'PY'\n"+code+'\nPY'],capture_output=True,text=True,timeout=5)
            if r.returncode==0:
                value=json.loads(r.stdout)
                if value.get('latest_attempt'):
                    t=a.directory/'last-attempt.tmp';t.write_text(json.dumps(value['latest_attempt']));os.replace(t,a.directory/'last-attempt.json')
                if value.get('capture'):
                    capture=value['capture'];capture['read_utc']=datetime.now(timezone.utc).isoformat()
                    t=a.directory/'last-capture.tmp';t.write_text(json.dumps(capture));os.replace(t,a.directory/'last-capture.json')
                if value.get('observer'):
                    import base64
                    observer=value['observer'];data=base64.b64decode(observer.pop('frame_base64'),validate=True)
                    observer['view']['source_run_id']=a.run_id
                    if data.startswith(b'\xff\xd8') and len(data)<=524288:
                        t=a.directory/'observer.tmp';t.write_bytes(data);os.replace(t,a.directory/'observer.jpg')
                        t=a.directory/'observer-status.tmp';t.write_text(json.dumps(observer['view']));os.replace(t,a.directory/'observer.json')
            else:errors+=1
        except (OSError,ValueError,subprocess.TimeoutExpired):errors+=1
        time.sleep(5)
    print(json.dumps({'stopped':True,'read_only':True,'transport_errors':errors}),flush=True)


if __name__=='__main__':main()
