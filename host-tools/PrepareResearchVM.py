"""Build a private Ubuntu base from pinned downloads, without candidate visits."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
import zipfile

from ResearchPaths import validate_region, pinned_host_line, ssh_configuration
from RunQemuResearch import available_ram

ROOT = Path(__file__).resolve().parents[1]
REPLICATION = ROOT / 'replication'


def digest(path, algorithm='sha256'):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def download(entry, directory):
    target = directory / entry['filename']
    if target.exists():
        if digest(target, entry['algorithm']) == entry['digest']:
            return target
        raise ValueError('Cached download changed; preserve and move it before retrying: ' + str(target))
    partial = target.with_suffix(target.suffix + '.partial')
    if partial.exists():
        raise ValueError('An unfinished download is preserved at ' + str(partial) + '. Move it before retrying.')
    print('Downloading ' + entry['url'], flush=True)
    request = urllib.request.Request(entry['url'], headers={'User-Agent': 'PhishingStudySetup/1'})
    with urllib.request.urlopen(request, timeout=45) as response, partial.open('xb') as stream:
        if not response.url.startswith('https://'):
            raise ValueError('HTTPS downloads are required.')
        shutil.copyfileobj(response, stream)
    if digest(partial, entry['algorithm']) != entry['digest']:
        raise ValueError('Download checksum mismatch; preserved ' + str(partial))
    partial.rename(target)
    return target


def verified_inputs(archive, target):
    manifest = json.loads((REPLICATION/'inputs-manifest.json').read_text())
    if digest(archive) != manifest['archive']['sha256'] or archive.stat().st_size != manifest['archive']['bytes']:
        raise ValueError('The study input archive differs from the frozen release.')
    target.mkdir()
    with zipfile.ZipFile(archive) as z:
        if len(z.infolist()) != len(manifest['files']) or set(z.namelist()) != set(manifest['files']):
            raise ValueError('Unexpected input archive entries.')
        for name, entry in manifest['files'].items():
            info = z.getinfo(name)
            if info.file_size != entry['bytes'] or '/' in name or '\\' in name:
                raise ValueError('Invalid input archive member.')
            with z.open(info) as source, (target/name).open('xb') as dest:
                shutil.copyfileobj(source, dest)
            if digest(target/name) != entry['sha256']:
                raise ValueError('Input checksum mismatch: ' + name)
    shutil.copyfile(REPLICATION/'inputs-manifest.json', target/'inputs-manifest.json')
    return manifest


def make_seed(path, operator_key, host_private, host_public):
    import pycdlib
    content = {'hostname': 'phishing-study-ubuntu', 'preserve_hostname': False,
        'manage_etc_hosts': True, 'ssh_pwauth': False, 'disable_root': True,
        'users': [{'name': 'studyadmin', 'groups': ['sudo'], 'shell': '/bin/bash',
            'lock_passwd': True, 'sudo': ['ALL=(ALL) NOPASSWD:ALL'],
            'ssh_authorized_keys': [operator_key.strip()]}],
        'ssh_keys': {'ed25519_private': host_private, 'ed25519_public': host_public},
        'write_files': [{'path': '/etc/ssh/sshd_config.d/60-research.conf', 'permissions': '0644',
            'content': 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n'}]}
    files = {'user-data': '#cloud-config\n'+json.dumps(content, indent=2)+'\n',
        'meta-data': json.dumps({'instance-id': 'study-'+uuid.uuid4().hex,
                                'local-hostname': 'phishing-study-ubuntu'})+'\n'}
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge='1.09', vol_ident='cidata')
    for index, (name, text) in enumerate(files.items()):
        value = text.encode()
        iso.add_fp(io.BytesIO(value), len(value), iso_path='/SEED'+str(index)+'.;1',
            rr_name=name, joliet_path='/'+name)
    iso.write(str(path)); iso.close()


def build(a):
    if os.name != 'nt':
        raise ValueError('This setup entry point supports Windows x64 with WHPX.')
    region = validate_region(a.region)
    home = ROOT / '.local-vm/portable'
    downloads = home/'downloads'; downloads.mkdir(parents=True, exist_ok=True)
    entries = json.loads((REPLICATION/'downloads.json').read_text())
    packages = {name: download(entries[name], downloads) for name in ('7zr','7zip','qemu','ubuntu')}
    expected = json.loads((REPLICATION/'inputs-manifest.json').read_text())['archive']
    archive = a.inputs_archive.resolve() if a.inputs_archive else download({
        'url':'https://github.com/Lawrken/phishing-study-implementation/releases/download/replication-v1/study-inputs-v1.zip',
        'filename':expected['name'],'algorithm':'sha256','digest':expected['sha256']},downloads)
    if digest(archive) != expected['sha256'] or archive.stat().st_size != expected['bytes']:
        raise ValueError('Input release checksum mismatch.')
    if a.downloads_only:
        print('All downloads are present and verified. No VM was started.'); return 0
    if available_ram() < 5 or shutil.disk_usage(ROOT).free < 50*2**30:
        raise ValueError('Setup needs 5 GiB available RAM and 50 GiB free space. No VM started.')
    if any(shutil.which(name) is None for name in ('ssh','scp','ssh-keygen')):
        raise ValueError('Windows OpenSSH Client (ssh, scp, ssh-keygen) is required.')
    control = ROOT/'.operator'; control.mkdir(exist_ok=True)
    configuration = a.configuration_output.resolve() if a.configuration_output else control/'host.json'
    if not configuration.is_relative_to(ROOT) or configuration.exists():
        raise ValueError('A fresh configuration path inside this clone is required. Existing setup is preserved.')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    work = home/('build-'+stamp); work.mkdir()
    logfile = work/'setup.log'
    def command(argv, timeout=300):
        with logfile.open('a', encoding='utf-8') as log:
            print('Running '+Path(argv[0]).name, flush=True)
            subprocess.run(list(map(str,argv)),stdout=log,stderr=subprocess.STDOUT,check=True,timeout=timeout)
    extract = work/'7zip'
    command([packages['7zr'],'x',packages['7zip'],'-o'+str(extract),'-y'])
    runtime = work/'qemu'
    command([extract/'7z.exe','x',packages['qemu'],'-o'+str(runtime),'-y'])
    for binary in ('qemu-system-x86_64.exe','qemu-img.exe'):
        if not (runtime/binary).is_file():
            raise ValueError('Unexpected QEMU archive layout. See '+str(logfile))
    base = work/'prepared-base.qcow2'
    command([runtime/'qemu-img.exe','convert','-O','qcow2',packages['ubuntu'],base], timeout=120)
    command([runtime/'qemu-img.exe','resize',base,'40G'])
    private = work/'private'; private.mkdir()
    # Each computer has different administration and host SSH identities.
    for name in ('operator_key','host_key'):
        command(['ssh-keygen','-q','-t','ed25519','-N','','-C','research-'+name,'-f',private/name])
    known = private/'known_hosts'
    known.write_text(pinned_host_line((private/'host_key.pub').read_text()))
    value = {'schema_version':1,'region':region,'qemu_directory':str(runtime),
        'base_disk':str(base),'base_format':'qcow2','base_sha256':'0'*64,
        'guest_user':'studyadmin','identity_file':str(private/'operator_key'),
        'known_hosts_file':str(known),'legacy_owner_installation':False}
    config = private/'ssh_config'; config.write_text(ssh_configuration(value, known))
    seed = private/'seed.iso'
    make_seed(seed,(private/'operator_key.pub').read_text(),(private/'host_key').read_text(),(private/'host_key.pub').read_text())
    inputs = work/'inputs'; verified_inputs(archive,inputs)
    for port in (22243,44443):
        with socket.socket() as probe:probe.bind(('127.0.0.1',port))
    args = [str(runtime/'qemu-system-x86_64.exe'),'-no-user-config','-nodefaults','-machine','pc',
        '-accel','whpx','-cpu','host','-smp','2,sockets=1,cores=2,threads=1','-m','4096',
        '-L',str(runtime/'share'),'-display','none','-vga','none','-monitor','none',
        '-serial','file:'+str(work/'serial.log'),'-rtc','base=utc,clock=host','-no-reboot',
        '-boot','order=c,strict=on','-drive','file='+str(base)+',format=qcow2,if=ide,index=0',
        '-drive','file='+str(seed)+',format=raw,media=cdrom,readonly=on',
        '-netdev','user,id=net0,hostfwd=tcp:127.0.0.1:22243-:22',
        '-device','e1000,netdev=net0,mac=08:00:27:0a:d2:be,addr=0x3']
    ssh = ['ssh','-F',str(config),'-o','ConnectTimeout=3','-o','ServerAliveInterval=5',
           '-o','ServerAliveCountMax=2','study-vm']
    print('Booting the new Ubuntu setup VM. Logs: '+str(work),flush=True)
    vm = None; success=False
    try:
        with (work/'qemu-console.txt').open('x') as console:
            vm=subprocess.Popen(args,stdout=console,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
        deadline=time.monotonic()+240
        while time.monotonic()<deadline:
            if vm.poll() is not None:raise RuntimeError('Setup VM exited. Inspect qemu-console.txt; WHPX is required.')
            try:
                test=subprocess.run([*ssh,'true'],capture_output=True,timeout=12)
            except subprocess.TimeoutExpired:
                time.sleep(2)
                continue
            if test.returncode==0:break
            time.sleep(2)
        else:raise TimeoutError('Setup VM SSH deadline. Inspect serial.log and setup.log.')
        command([*ssh,'sudo -n cloud-init status --wait'],timeout=300)
        command([*ssh,'mkdir -m 700 /var/tmp/research-setup'])
        transfer=[REPLICATION/'bootstrap-guest.sh',REPLICATION/'requirements-guest.txt',*inputs.iterdir()]
        command(['scp','-F',config,*transfer,'study-vm:/var/tmp/research-setup/'],timeout=120)
        print('Installing pinned Python packages and Chromium inside Ubuntu. This may take several minutes.',flush=True)
        command([*ssh,'sudo -n bash /var/tmp/research-setup/bootstrap-guest.sh'],timeout=2700)
        command([*ssh,'sudo -n sync; sudo -n systemctl poweroff --no-block'])
        vm.wait(timeout=45)
        if vm.returncode!=0:raise RuntimeError('Setup VM did not exit cleanly.')
        value['base_sha256']=digest(base)
        configuration.write_text(json.dumps(value,indent=2)+'\n')
        (work/'setup-receipt.json').write_text(json.dumps({'status':'passed','configuration':str(configuration),
            'base_sha256':value['base_sha256'],'region':region,'collection_activation':False,
            'dataset_visits':0,'fresh_verification_required':True,'downloads':entries,
            'bootstrap_sha256':digest(REPLICATION/'bootstrap-guest.sh'),
            'requirements_guest_sha256':digest(REPLICATION/'requirements-guest.txt'),
            'inputs_archive_sha256':expected['sha256']},indent=2)+'\n')
        success=True
        print('Setup passed. Run ResearchOperator.ps1 -Mode Run -MaxAttempts 10 -VerifyOnly first.',flush=True)
        return 0
    finally:
        if vm is not None and vm.poll() is None:
            try:
                subprocess.run([*ssh,'sudo -n sync; sudo -n systemctl poweroff --no-block'],capture_output=True,timeout=15)
                vm.wait(timeout=45)
            except (subprocess.SubprocessError,OSError):
                vm.terminate();vm.wait(timeout=10)
        if not success:
            (work/'setup-failed.json').write_text(json.dumps({'status':'failed','collection_activation':False,
                'configuration_created':configuration.exists(),'logs_preserved':True})+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--region',required=True)
    parser.add_argument('--inputs-archive',type=Path)
    parser.add_argument('--downloads-only',action='store_true')
    parser.add_argument('--configuration-output',type=Path,help='Fresh workspace path for a rehearsal; leaves the owner setup unchanged')
    return build(parser.parse_args())


if __name__=='__main__':
    raise SystemExit(main())
