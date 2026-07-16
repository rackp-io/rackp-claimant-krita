"""Persistent settings for the RACKP Claimant Krita plugin.

Stored in $RACKP_HOME/claimant.json (default ~/.rackp/claimant.json). The
RACKP_HOME override exists so tests can use a scratch directory instead of the
user's real profile.

Identity is persisted as the 32-byte Ed25519 seed (Base64url) plus the
terminal_id, from which a TerminalIdentity is reconstructed on each launch.
sequence_number and `registered` persist the anchor chain's continuity across
restarts (the chain must stay monotonic for the life of the terminal).
"""
import json
import os
from pathlib import Path


def _home() -> Path:
    return Path(os.environ.get("RACKP_HOME", str(Path.home() / ".rackp")))


def config_path() -> Path:
    return _home() / "claimant.json"


_defaults = {
    "terminal_id": None,        # UUID v4, generated on first run
    "secret_b64url": None,      # 32-byte Ed25519 seed, Base64url (unpadded)
    "public_key": None,         # Base64url Ed25519 public key (for display)
    "sequence_number": 0,       # last anchored sequence_number (monotonic)
    "registered": False,        # Keeper has confirmed the public key
    "keeper_url": "https://keeper.rackp.io",
    "referee_url": "https://referee.rackp.io",
    "norm_profile_id": "rackp.standard.v1",
    "norm_fetch_url": "https://rackp.io/norms/rackp-standard-v1.json",
    # Per-file anchor info: { filepath: {claim_id, data_hash, sequence, timestamp,
    #   file_base64, anchor_count} }
    "file_anchors": {},
    # Incidents: { incident_id: {description, actor_id, filepath, status, created_at,
    #   anchor: {...}, result: {...}} }
    "incidents": {},
}


def load() -> dict:
    path = config_path()
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in _defaults.items():
            data.setdefault(k, v)
        return data
    return {k: (dict(v) if isinstance(v, dict) else v) for k, v in _defaults.items()}


def save(config: dict) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
