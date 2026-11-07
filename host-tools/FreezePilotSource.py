"""Freeze maintained source into a fresh, hash-bound installation archive."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'phishing-study'
sys.path.insert(0, str(APP))
from study.deployment import source_files, source_hash, file_hash

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    destination = args.output.resolve()
    assert destination.is_relative_to(ROOT) and not destination.exists()
    files = source_files(APP)
    identity = source_hash(APP)
    destination.mkdir()
    archive = destination / 'source.tar.gz'
    with tarfile.open(archive, 'x:gz') as stream:
        for path in files:
            stream.add(path, arcname='app/' + path.relative_to(APP).as_posix())
    manifest = {'utc': datetime.now(timezone.utc).isoformat(), 'source_hash': identity,
        'source_files': len(files), 'files': {p.relative_to(APP).as_posix(): file_hash(p) for p in files},
        'archive_sha256': file_hash(archive)}
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    assert source_hash(APP) == identity
    print(json.dumps({k:v for k,v in manifest.items() if k != 'files'}, indent=2))

if __name__ == '__main__':
    main()
