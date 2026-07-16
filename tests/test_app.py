"""Application-layer conformance (app.ClaimantApp), Krita-independent.

Exercises identity persistence, save-anchoring with the base64 evidence cache,
anchor-chain continuity across ClaimantApp rebuilds, and an empty mailbox poll —
the plugin's keeper-facing behaviour without Krita or Qt.

Offline (default): MockTransport. Live: RACKP_KEEPER_URL against wrangler-dev.
Uses RACKP_HOME so it never touches the real ~/.rackp.

    python tests/test_app.py
    RACKP_KEEPER_URL=http://127.0.0.1:8788 python tests/test_app.py
"""
import os
import sys
import tempfile

_TMP = tempfile.mkdtemp(prefix="rackp_app_test_")
os.environ["RACKP_HOME"] = _TMP

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rackp_claimant import settings
from rackp_claimant.app import ClaimantApp
from rackp_claimant.transport import MockTransport

passed = 0


def ok(name):
    global passed
    passed += 1
    print(f"  ok: {name}")


def make_app(keeper_url, live, shared_mock=None):
    cfg = settings.load()
    cfg["keeper_url"] = keeper_url
    settings.save(cfg)
    if live:
        return ClaimantApp(cfg)
    return ClaimantApp(cfg, transport=shared_mock)


def run(keeper_url, live):
    mock = None if live else MockTransport()

    app = make_app(keeper_url, live, mock)
    tid = app.terminal_id
    assert tid and app.config["secret_b64url"]
    ok("first run generates and persists an identity")

    # Persistence: a fresh app instance reuses the same identity.
    app2 = make_app(keeper_url, live, mock)
    assert app2.terminal_id == tid
    ok("identity persists across ClaimantApp rebuilds")

    app2.session_start()
    assert app2.claimant.anchors._seq == 1 and app2.config["registered"]
    ok("session_start anchors SESSION_START (seq 1) and records registration")

    # Anchor a saved file: payload is {"file_base64": ...}, cached for evidence.
    f = os.path.join(_TMP, "art.kra")
    with open(f, "wb") as fh:
        fh.write(b"PK\x03\x04 fake kra bytes")
    rec = app2.anchor_file(f)
    assert rec.sequence_number == 2
    cache = settings.load()["file_anchors"][f]
    assert cache["data_hash"] == rec.data_hash and cache["file_base64"]
    assert cache["anchor_count"] == 1
    ok("anchor_file caches the base64 payload + data_hash for later evidence")

    # Re-save the same file: monotonic sequence, anchor_count increments.
    rec2 = app2.anchor_file(f)
    assert rec2.sequence_number == 3
    assert settings.load()["file_anchors"][f]["anchor_count"] == 2
    ok("re-anchoring the same file is monotonic and bumps anchor_count")

    # Chain continuity: a rebuilt app resumes at the persisted sequence.
    app3 = make_app(keeper_url, live, mock)
    assert app3.claimant.anchors._seq == 3 and app3.claimant.anchors.registered
    rec3 = app3.anchor_log("d" * 64)
    assert rec3.sequence_number == 4
    ok("a rebuilt app resumes the anchor chain at the persisted sequence")

    # Mailbox poll (empty) does not raise and returns no notes.
    notes = app3.poll()
    assert notes == []
    ok("empty mailbox poll returns no notes")


if __name__ == "__main__":
    url = os.environ.get("RACKP_KEEPER_URL")
    if url:
        run(url, live=True)
        print(f"\nall {passed} checks passed against LIVE {url}  (RACKP_HOME={_TMP})")
    else:
        run("mock://keeper", live=False)
        print(f"\nall {passed} checks passed against mock keeper  (RACKP_HOME={_TMP})")
