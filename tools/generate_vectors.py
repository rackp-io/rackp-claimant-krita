"""Generate the published RACKP protocol test vectors (rackp/schemas/test-vectors/).

Run:  python tools/generate_vectors.py
Output is deterministic: re-running must produce byte-identical files.

Writes to ../rackp/schemas/test-vectors, so the rackp repo must be checked out
as a sibling. The reference Claimant's pure-Python ed25519 / jcs (this package)
are the source of truth for the vectors; their correctness is guarded by
tests/test_conformance.py (RFC 8032 Section 7.1 TEST 1-3).

The secret key below is deliberately public and burned — it exists only so that
independent implementations can compare intermediate values (canonical bytes,
hashes, signatures). It must never be used as a real terminal identity.
"""

import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from rackp_claimant import ed25519, jcs
from rackp_claimant.identity import b64url_encode

OUT = HERE.parent.parent / "rackp" / "schemas" / "test-vectors"

BURNED_SECRET = bytes(range(32))  # 000102...1f
PUBLIC_KEY = ed25519.public_key(BURNED_SECRET)


def write(name: str, doc: dict):
    OUT.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
    (OUT / name).write_text(text, encoding="utf-8", newline="\n")
    print("wrote", OUT / name)


# --- 1. JCS canonicalization (RFC 8785) ---------------------------------------

JCS_CASES = [
    ("object keys sorted by UTF-16 code units", {"b": 1, "a": 2}),
    ("ascii key sorts before non-ascii key", {"あ": "unicode key", "A": "ascii key"}),
    ("string escapes: control chars, quote, backslash",
     {"s": "line\nbreak\ttab \"quote\" back\\slash \x01"}),
    ("non-ascii characters are emitted literally", {"msg": "日本語テキスト"}),
    ("numbers: integers and integral float serialize alike", {"n": [0, -1, 1.0, 42]}),
    ("empty containers and empty string", {"empty_obj": {}, "empty_arr": [], "empty_str": ""}),
    ("nested structures and literals", {"x": [{"k": None, "t": True, "f": False}]}),
]

write("jcs.json", {
    "description": "JCS (RFC 8785) canonicalization vectors. 'canonical' is the exact UTF-8 string whose bytes are hashed (data_hash) and signed (signature). An implementation conforms if canonicalize(input) equals canonical, byte for byte.",
    "vectors": [
        {"description": d, "input": v, "canonical": jcs.canonicalize(v).decode("utf-8")}
        for d, v in JCS_CASES
    ],
})

# --- 2. Message signatures ------------------------------------------------------


def sig_vector(description: str, body: dict) -> dict:
    canonical = jcs.canonicalize(body)
    return {
        "description": description,
        "message_body": body,
        "canonical": canonical.decode("utf-8"),
        "signature": b64url_encode(ed25519.sign(BURNED_SECRET, canonical)),
    }


write("signature.json", {
    "description": "Message signature vectors. The signature is Ed25519 over the JCS canonicalization of the message body (all fields except 'signature'), encoded as unpadded Base64url. The secret key is deliberately public and burned: never use it as a real terminal identity.",
    "secret_key_hex": BURNED_SECRET.hex(),
    "public_key": b64url_encode(PUBLIC_KEY),
    "vectors": [
        sig_vector("minimal object", {"type": "PING", "value": 42}),
        sig_vector(
            "FEE_REFUND_CLAIM body (signature field excluded from signing input)",
            {
                "type": "FEE_REFUND_CLAIM",
                "incident_id": "33333333-3333-4333-8333-333333333333",
                "depositor_id": "11111111-1111-4111-8111-111111111111",
                "timestamp": "2026-01-01T00:00:00Z",
            },
        ),
    ],
})

# --- 3. CLAIM_ANCHOR end-to-end ---------------------------------------------------

payload = {
    "event": "draft_saved",
    "strokes": 412,
    "duration_s": 95,
    "note": "手描きセッション",
    "ratio": 1.0,
}
payload_canonical = jcs.canonicalize(payload)
data_hash = hashlib.sha256(payload_canonical).hexdigest()

body = {
    "type": "CLAIM_ANCHOR",
    "terminal_id": "11111111-1111-4111-8111-111111111111",
    "claim_id": "22222222-2222-4222-8222-222222222222",
    "sequence_number": 1,
    "timestamp": "2026-01-01T00:00:00Z",
    "public_key": b64url_encode(PUBLIC_KEY),
    "data_hash": data_hash,
}
body_canonical = jcs.canonicalize(body)
signature = b64url_encode(ed25519.sign(BURNED_SECRET, body_canonical))
message = dict(body)
message["signature"] = signature

write("claim_anchor.json", {
    "description": "End-to-end CLAIM_ANCHOR vector covering the full pipeline: anchored_payload -> payload_canonical (JCS) -> data_hash (SHA-256 hex) -> message_body_canonical (JCS of all fields except signature) -> signature (Ed25519, unpadded Base64url). A conforming implementation reproduces every intermediate value exactly.",
    "secret_key_hex": BURNED_SECRET.hex(),
    "anchored_payload": payload,
    "payload_canonical": payload_canonical.decode("utf-8"),
    "data_hash": data_hash,
    "message_body_canonical": body_canonical.decode("utf-8"),
    "message": message,
})
