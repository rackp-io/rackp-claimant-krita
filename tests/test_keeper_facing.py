"""Keeper-facing conformance for the Claimant core against the reference Keeper.

Offline (default): runs the whole flow against the in-memory MockTransport.
Live: set RACKP_KEEPER_URL to a running rackp-keeper (e.g. wrangler dev at
http://127.0.0.1:8788) to exercise the real single-endpoint HTTP binding —
CLAIM_ANCHOR registration + monotonic sequence, idempotent redelivery,
FEE_DEPOSIT, FEE_REFUND_CLAIM (embedded FEE_REFUND_RESULT), and MAILBOX_QUERY.

    python tests/test_keeper_facing.py
    RACKP_KEEPER_URL=http://127.0.0.1:8788 python tests/test_keeper_facing.py
"""

import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rackp_claimant.identity import TerminalIdentity
from rackp_claimant.transport import HttpTransport, MockTransport, message_hash
from rackp_claimant.claimant import Claimant

passed = 0


def ok(name):
    global passed
    passed += 1
    print(f"  ok: {name}")


def run(keeper_url, identity, transport):
    c = Claimant(identity, keeper_url, transport)

    # SESSION_START (seq 1) registers the terminal via its public_key.
    rec = c.start_session([
        {"norm_profile_id": "rackp.standard.v1",
         "norm_fetch_url": "https://rackp.io/norms/rackp-standard-v1.json"},
    ])
    assert rec.sequence_number == 1 and c.anchors.registered
    ok("SESSION_START anchor (seq 1) registers the terminal")

    # A second anchor (seq 2) — monotonic, no public_key needed now.
    rec2 = c.anchor({"event": "draft_saved", "strokes": 12})
    assert rec2.sequence_number == 2
    ok("second CLAIM_ANCHOR accepted (monotonic sequence)")

    # Idempotent redelivery of identical bytes returns the original receipt.
    signed = identity.sign_message({
        "type": "CLAIM_ANCHOR", "terminal_id": identity.terminal_id,
        "claim_id": str(uuid.uuid4()), "sequence_number": 3,
        "timestamp": transport.now_iso8601(), "data_hash": "a" * 64,
    })
    r1 = transport.send(keeper_url, signed)
    r2 = transport.send(keeper_url, signed)
    assert r1 == r2 and r1["type"] == "DELIVERY_RECEIPT"
    assert r1["message_hash"] == message_hash(signed)
    ok("idempotent redelivery returns the identical original receipt")

    # A regressed sequence number is a definitive conflict. Use seq 2 (<= the max
    # of 3 already anchored): seq 1 would instead fail SCHEMA_VIOLATION, since
    # claim_anchor.json requires public_key at sequence 1.
    regressed = identity.sign_message({
        "type": "CLAIM_ANCHOR", "terminal_id": identity.terminal_id,
        "claim_id": str(uuid.uuid4()), "sequence_number": 2,
        "timestamp": transport.now_iso8601(), "data_hash": "b" * 64,
    })
    rej = transport.send(keeper_url, regressed)
    assert rej["type"] == "DELIVERY_REJECTION" and rej["reason"] == "SEQUENCE_CONFLICT"
    ok("non-monotonic sequence_number -> DELIVERY_REJECTION(SEQUENCE_CONFLICT)")

    # FEE_DEPOSIT into escrow for a fresh incident.
    incident = str(uuid.uuid4())
    c.deposit_fee(incident, 100, "USD")
    ok("FEE_DEPOSIT accepted")

    # FEE_REFUND_CLAIM before any deadline -> embedded FEE_REFUND_RESULT(REJECTED).
    result = c.claim_refund(incident)
    assert result["type"] == "FEE_REFUND_RESULT"
    assert result["status"] == "REJECTED"
    assert result["rejection_reason"] == "DEADLINE_NOT_ELAPSED"
    ok("FEE_REFUND_CLAIM -> receipt-embedded FEE_REFUND_RESULT(DEADLINE_NOT_ELAPSED)")

    # MAILBOX_QUERY returns held party-addressed messages (empty here).
    held = c.poll()
    assert isinstance(held, list)
    ok(f"MAILBOX_QUERY returns the mailbox ({len(held)} held)")


if __name__ == "__main__":
    url = os.environ.get("RACKP_KEEPER_URL")
    ident = TerminalIdentity()
    if url:
        run(url, ident, HttpTransport(identity=ident))
        print(f"\nall {passed} checks passed against LIVE {url}")
    else:
        run("mock://keeper", ident, MockTransport())
        print(f"\nall {passed} checks passed against mock keeper")
