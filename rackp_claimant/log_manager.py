"""
Session log manager for RACKP Claimant.
Accumulates operation events locally, computes a rolling hash for anchoring.
Logs are stored as JSON Lines in ~/.rackp/logs/<session_id>.jsonl
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

_LOG_DIR = Path.home() / '.rackp' / 'logs'


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


class SessionLog:
    def __init__(self, terminal_id: str):
        self.session_id = str(uuid.uuid4())
        self.terminal_id = terminal_id
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._path = _LOG_DIR / f'{self.session_id}.jsonl'
        self._last_hash: str | None = None
        self._append({'event': 'session_start', 'terminal_id': terminal_id})

    def record(self, event: str, **kwargs):
        """Append an event entry to the log."""
        self._append({'event': event, **kwargs})

    def hash(self) -> str:
        """SHA-256 of the entire log file so far."""
        with open(self._path, 'rb') as f:
            h = hashlib.sha256(f.read()).hexdigest()
        self._last_hash = h
        return h

    def has_changed_since_last_hash(self) -> bool:
        """True if the log has grown since the last hash was taken."""
        current = self.hash()
        return current != self._last_hash

    @property
    def path(self) -> Path:
        return self._path

    def _append(self, entry: dict):
        entry['ts'] = _now()
        with open(self._path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
