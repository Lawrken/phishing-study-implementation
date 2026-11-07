#!/usr/bin/env python3
"""Execute the current finite collector; resume keeps original run budgets."""
import asyncio
import json
from pathlib import Path

from study.config import load
from study.queue import Queue
from study.runner import collect

request = json.loads(Path('/etc/phishing-study/pilot-request.json').read_text())
config = load('/etc/phishing-study/pilot.toml')
queue = Queue('/var/lib/phishing-study/dataset')
print(json.dumps({'run_id': asyncio.run(collect(queue, config, request.get('resume')))}), flush=True)
