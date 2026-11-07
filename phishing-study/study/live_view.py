"""Optional bounded, replace-only VM screenshots for a view-only local monitor.

No additional page visits, browser interaction, HTML serving or network listener.
Images are outside the research dataset and are not used as model features.
"""
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path


class LiveView:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.frame_candidate_id = None
        if (not self.directory.is_dir() or self.directory.is_symlink()
                or self.directory.stat().st_uid != os.geteuid()
                or self.directory.stat().st_mode & 0o077):
            raise ValueError('private_owned_live_view_directory_required')

    @classmethod
    def from_environment(cls):
        path = os.environ.get('STUDY_LIVE_VIEW')
        return cls(path) if path else None

    def write(self, name, data):
        target = self.directory / name
        temporary = self.directory / (name + '.tmp')
        if target.is_symlink() or temporary.is_symlink():
            raise ValueError('live_view_symlink_denied')
        with temporary.open('wb') as stream:
            stream.write(data)
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)

    def state(self, item, stage, **extra):
        from .urls import safe_url
        self.write('status.json', json.dumps({'candidate_id': item['id'],
            'frame_candidate_id': self.frame_candidate_id,
            'origin': safe_url(item.get('url', '')).get('origin'), 'label': item.get('label'),
            'stage': stage, 'utc': datetime.now(timezone.utc).isoformat(), **extra}).encode())

    async def frames(self, page, item, signals):
        while not page.is_closed():
            try:
                data = await page.screenshot(type='jpeg', quality=35, full_page=False,
                                             scale='css', timeout=800)
                if data.startswith(b'\xff\xd8') and len(data) <= 524288:
                    self.write('latest.jpg', data)
                    self.frame_candidate_id = item['id']
                    self.state(item, 'browser observing', frame_bytes=len(data), signals=signals())
            except asyncio.CancelledError:
                raise
            except Exception:
                # This display is optional. It cannot change research eligibility
                # or disable the independent logging/storage/containment checks.
                pass
            await asyncio.sleep(2)
