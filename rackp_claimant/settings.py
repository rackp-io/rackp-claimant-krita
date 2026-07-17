"""Persistent settings for the RACKP Claimant Krita plugin.

Split across four files under $RACKP_HOME (default ~/.rackp):

  identity.json   terminal identity + anchor-chain state (terminal_id, Ed25519
                  seed, public key, sequence_number, registered). Small and
                  precious — losing it means losing the terminal's identity —
                  so it is never mixed with data a user may want to edit or
                  reset by hand.
  anchors.json    per-file anchor cache (includes cached file content as
                  base64). Bulky but reconstructible.
  incidents.json  assessment / incident bookkeeping. Safe to reset to {} while
                  Krita is closed.
  config.json     endpoints, Norm profile, and any remaining keys (e.g. the
                  mailbox cursor).

The public API is unchanged: load() returns one merged dict and save() splits
it back into the four files. Every file is written atomically (temp file +
os.replace) and only when its content actually changed, so a crash mid-write
can no longer corrupt the identity, and re-saving a large anchor cache is
skipped when only incident state moved.

A legacy single-file claimant.json is migrated to this layout on first load
and kept as claimant.json.bak.

The RACKP_HOME override exists so tests can use a scratch directory instead of
the user's real profile.
"""
import json
import os
from pathlib import Path


def _home() -> Path:
    return Path(os.environ.get("RACKP_HOME", str(Path.home() / ".rackp")))


_IDENTITY_KEYS = (
    "terminal_id", "secret_b64url", "public_key", "sequence_number", "registered",
)

# filename -> extracts that file's slice from the merged config. config.json is
# the catch-all so unknown/future keys survive a load/save round-trip.
_FILES = {
    "identity.json": lambda c: {k: c.get(k) for k in _IDENTITY_KEYS},
    "anchors.json": lambda c: {"file_anchors": c.get("file_anchors", {})},
    "incidents.json": lambda c: {"incidents": c.get("incidents", {})},
    "config.json": lambda c: {
        k: v for k, v in c.items()
        if k not in _IDENTITY_KEYS and k not in ("file_anchors", "incidents")
    },
}

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


def _apply_defaults(data: dict) -> dict:
    for k, v in _defaults.items():
        data.setdefault(k, dict(v) if isinstance(v, dict) else v)
    return data


def load() -> dict:
    home = _home()
    legacy = home / "claimant.json"
    if legacy.exists() and not any((home / name).exists() for name in _FILES):
        with open(legacy, "r", encoding="utf-8") as f:
            data = _apply_defaults(json.load(f))
        save(data)  # write the new four-file layout
        os.replace(legacy, home / "claimant.json.bak")
        return data

    data = {}
    for name in _FILES:
        path = home / name
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data.update(json.load(f))
    return _apply_defaults(data)


def save(config: dict) -> None:
    home = _home()
    home.mkdir(parents=True, exist_ok=True)
    for name, slice_fn in _FILES.items():
        text = json.dumps(slice_fn(config), indent=2, ensure_ascii=False)
        path = home / name
        if path.exists():
            try:
                if path.read_text(encoding="utf-8") == text:
                    continue  # unchanged — skip the rewrite entirely
            except OSError:
                pass
        tmp = home / (name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
