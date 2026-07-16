"""Live end-to-end: ClaimantApp -> rackp-referee -> rackp-keeper (PoHI flow).

Drives the full no-Actor certification loop over real HTTP, exactly as the
Krita plugin would: anchor a file (with the PoHI binding in the payload),
deposit the sole-requester fee, file the assessment, then let the mailbox
poller do the rest — auto-submit evidence on EVIDENCE_QUERY_REQUEST and
receive the POH_CERTIFICATE. Also pins the non-destructive-mailbox dedup:
a second poll must not re-process anything.

LIVE-only (needs both wrangler dev instances with FRESH local DBs):
  (keeper)   cd ../rackp-keeper  && npm run db:migrate:local && npx wrangler dev --port 8788
  (referee)  cd ../rackp-referee && npm run db:migrate:local && npx wrangler dev --port 8799 --test-scheduled

  RACKP_KEEPER_URL=http://127.0.0.1:8788 RACKP_REFEREE_URL=http://127.0.0.1:8799 \
      python tests/test_referee_e2e.py

Also runs against production endpoints as a deployment smoke: without the
--test-scheduled hook the referee's real cron (*/5) paces each delivery leg,
so allow ~10-15 minutes end to end.
"""
import hashlib
import os
import sys
import tempfile
import time
import urllib.request

KEEPER = os.environ.get("RACKP_KEEPER_URL")
REFEREE = os.environ.get("RACKP_REFEREE_URL")
if not KEEPER or not REFEREE:
    print("skipped: set RACKP_KEEPER_URL and RACKP_REFEREE_URL for the live E2E")
    sys.exit(0)

_TMP = tempfile.mkdtemp(prefix="rackp_e2e_test_")
os.environ["RACKP_HOME"] = _TMP

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rackp_claimant import settings
from rackp_claimant.app import ClaimantApp

passed = 0


def ok(name):
    global passed
    passed += 1
    print(f"  ok: {name}")


def cron():
    """Best-effort drain of the referee's outbound queue. Against wrangler dev
    (--test-scheduled) this triggers the cron instantly; against production the
    URL falls through to the GET profile handler and the REAL cron (*/5) paces
    delivery instead — wait_for_note absorbs the difference."""
    try:
        with urllib.request.urlopen(f"{REFEREE}/__scheduled?cron=*+*+*+*+*", timeout=15) as r:
            r.read()
    except Exception:
        pass
    time.sleep(0.2)


def wait_for_note(app, substr, timeout_s, tick_s=20):
    """Poll the mailbox (nudging the dev cron each tick) until a note containing
    `substr` appears. Dev: first tick. Production: up to one 5-minute cron cycle
    per delivery leg."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        cron()
        notes = app.poll()
        if any(substr in n for n in notes):
            return notes
        time.sleep(tick_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for a note containing {substr!r}")


cfg = settings.load()
cfg["keeper_url"] = KEEPER
cfg["referee_url"] = REFEREE
settings.save(cfg)
app = ClaimantApp(cfg)

# Phase 1: session + continuous anchoring (5 anchors in the window -> HIGH density).
app.session_start()
artifact = os.path.join(_TMP, "drawing.kra")
with open(artifact, "wb") as f:
    f.write(b"PK\x03\x04 layered art bytes")
for _ in range(4):
    rec = app.anchor_file(artifact)
subject_hash = hashlib.sha256(open(artifact, "rb").read()).hexdigest()
cache = settings.load()["file_anchors"][artifact]
assert cache["payload"]["pohi"]["subject_data_hash"] == subject_hash
ok("anchor_file carries the PoHI artifact binding inside the anchored payload")

# Phase 2: file the no-Actor assessment, then deposit against its incident
# (the sole requester bears the full fee, STD-029).
incident_id = app.file_assessment("PoHI for drawing.kra", artifact, actor_id=None)
app.claimant.deposit_fee(incident_id, 200, "USD")
ok(f"no-Actor ASSESSMENT_REQUEST filed ({incident_id[:8]}...) and fee deposited")

# The referee's outbound queue delivers EVIDENCE_QUERY_REQUEST to the mailbox.
wait_for_note(app, "証拠を提出", timeout_s=600)
ok("mailbox poll auto-submits the anchored evidence on EVIDENCE_QUERY_REQUEST")

# The submission triggers assessment; the next drain delivers the certificate.
wait_for_note(app, "人間関与証明書", timeout_s=600)
inc = settings.load()["incidents"][incident_id]
assert inc["status"] == "POH_CERTIFICATE"
cert = inc["result"]
assert cert["type"] == "POH_CERTIFICATE"
assert cert["subject_terminal_id"] == app.terminal_id
assert cert["subject_data_hash"] == subject_hash, "certificate binds the exact artifact"
assert cert["provenance"]["human_ratio"] == 1.0 and cert["provenance"]["confidence_level"] == "HIGH"
ok("POH_CERTIFICATE received via the mailbox, bound to the artifact, HIGH density")

# Dedup: the keeper mailbox read is non-destructive — a re-poll must be silent.
notes = app.poll()
assert notes == [], f"re-poll must not re-process held messages, got {notes}"
assert settings.load().get("mailbox_since"), "since cursor persisted"
ok("non-destructive mailbox re-poll is absorbed (since cursor + processed ledger)")

print(f"\nall {passed} E2E checks passed against referee={REFEREE} keeper={KEEPER}  (RACKP_HOME={_TMP})")
