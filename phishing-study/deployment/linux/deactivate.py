#!/usr/bin/env python3
"""Archive an activation flag without deleting pilot data or evidence."""
import os
from pathlib import Path
import uuid

from study.deployment import ETC, secure_root_file

if os.geteuid() != 0:
    raise SystemExit('Only root can archive activation flags')
suffix = uuid.uuid4().hex
for name in ('pilot.toml', 'activation.json'):
    path = Path(ETC) / name
    if path.exists() or path.is_symlink():
        secure_root_file(path).rename(path.with_name(name + '.inactive-' + suffix))
