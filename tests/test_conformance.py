"""Conformance harness: crypto correctness + every emitted message against
rackp/schemas/. This is the coverage that guards the pure-Python crypto and the
message shapes; the live keeper-facing behaviour is in test_keeper_facing.py.

Requires `jsonschema` and `referencing` (present in the sim venv), and the rackp
repo checked out as a sibling (../rackp) for the schemas.

Run: python tests/test_conformance.py
"""

import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
SCHEMA_DIR = HERE.parent.parent / "rackp" / "schemas"

import jsonschema
from referencing import Registry, Resource

from rackp_claimant.claimant import Claimant
from rackp_claimant.transport import MockTransport
from rackp_claimant.identity import TerminalIdentity, verify_message, b64url_encode
from rackp_claimant import ed25519, jcs

RESULTS = []


def check(name: str, ok: bool, detail: str = ""):
    RESULTS.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail}" if detail and not ok else ""))


# --- schema registry ---------------------------------------------------------

def load_registry():
    resources = []
    docs = {}
    for f in SCHEMA_DIR.glob("*.json"):
        doc = json.loads(f.read_text(encoding="utf-8-sig"))
        docs[f.name] = doc
        if "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc)))
    return Registry().with_resources(resources), docs


REGISTRY, SCHEMAS = load_registry()


def validate(message: dict, schema_file: str) -> tuple[bool, str]:
    validator = jsonschema.Draft202012Validator(SCHEMAS[schema_file], registry=REGISTRY)
    errors = sorted(validator.iter_errors(message), key=lambda e: e.json_path)
    if errors:
        return False, "; ".join(f"{e.json_path}: {e.message}" for e in errors[:3])
    return True, ""


# --- 1. crypto self-consistency ----------------------------------------------

secret = bytes(range(32))
pub = ed25519.public_key(secret)
msg = b"rackp clean-room test"
sig = ed25519.sign(secret, msg)
check("ed25519 sign/verify round-trip", ed25519.verify(pub, msg, sig))
check("ed25519 rejects tampered message", not ed25519.verify(pub, msg + b"x", sig))
check("ed25519 rejects tampered signature",
      not ed25519.verify(pub, msg, sig[:-1] + bytes([sig[-1] ^ 1])))
check("ed25519 deterministic", ed25519.sign(secret, msg) == sig)

# RFC 8032 §7.1 official test vectors (TEST 1-3)
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]
for i, (sk, pk, msg_hex, sig_hex) in enumerate(RFC8032, 1):
    sk_b = bytes.fromhex(sk)
    m_b = bytes.fromhex(msg_hex)
    check(f"RFC 8032 TEST {i}: public key derivation",
          ed25519.public_key(sk_b).hex() == pk)
    check(f"RFC 8032 TEST {i}: signature matches official vector",
          ed25519.sign(sk_b, m_b).hex() == sig_hex)
    check(f"RFC 8032 TEST {i}: official signature verifies",
          ed25519.verify(bytes.fromhex(pk), m_b, bytes.fromhex(sig_hex)))

# --- 2. JCS sanity -------------------------------------------------------------

check("jcs key ordering",
      jcs.canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}')
check("jcs nested + escapes",
      jcs.canonicalize({"x": ["a\n", {"k": None}], "1": True})
      == b'{"1":true,"x":["a\\n",{"k":null}]}')
check("jcs integral float", jcs.canonicalize(1.0) == b"1")

# --- 3. full Claimant flow -----------------------------------------------------

transport = MockTransport()
identity = TerminalIdentity()
KC = "https://kc.example/keeper"
REFEREE = "https://referee.example/api"

c = Claimant(identity, KC, transport)

# Phase 1: session + anchoring
norms = [{
    "norm_profile_id": "rackp.standard.v1",
    "norm_fetch_url": "https://raw.githubusercontent.com/rackp-io/rackp/main/norms/rackp-standard-v1.json",
}]
session_rec = c.start_session(norms)
session_msg = transport.keeper(KC).anchors[identity.terminal_id][0]
ok, err = validate(session_msg, "claim_anchor.json")
check("CLAIM_ANCHOR (SESSION_START, seq=1) conforms to schema", ok, err)
check("seq=1 anchor carries public_key", "public_key" in session_msg)

rec1 = c.anchor({"event": "draft_saved", "strokes": 412, "duration_s": 95})
rec2 = c.anchor({"event": "draft_saved", "strokes": 530, "duration_s": 142})
last_anchor_msg = transport.keeper(KC).anchors[identity.terminal_id][-1]
ok, err = validate(last_anchor_msg, "claim_anchor.json")
check("CLAIM_ANCHOR (data, seq>1) conforms to schema", ok, err)
check("seq>1 anchor omits public_key", "public_key" not in last_anchor_msg)

check("Keeper stub accepted all anchors (signatures verified)",
      len(transport.keeper(KC).anchors[identity.terminal_id]) == 3)

# Keeper-style independent signature verification
pub_b64 = transport.keeper(KC).public_keys[identity.terminal_id]
check("independent verify path (Keeper role) accepts anchor signature",
      verify_message(pub_b64, last_anchor_msg))
tampered = dict(last_anchor_msg, data_hash="0" * 64)
check("independent verify path rejects tampered anchor",
      not verify_message(pub_b64, tampered))

# Phase 2: PoHI filing (no Actor)
pohi_req = c.file_assessment(
    REFEREE,
    incident_summary="PoHI certification request for artifact X",
    incident_timestamp="2026-06-12T03:00:00Z",
    norm_profile_ids=["rackp.standard.v1"],
)
ok, err = validate(pohi_req, "assessment_request.json")
check("ASSESSMENT_REQUEST (PoHI, no actor) conforms to schema", ok, err)

# Phase 2: two-party filing
incident_req = c.file_assessment(
    REFEREE,
    incident_summary="Actor agent deleted shared resources",
    incident_timestamp="2026-06-12T02:30:00Z",
    actor_id="3f1d2c4b-aaaa-4bbb-8ccc-112233445566",
    actor_keeper_endpoint="https://ka.example/keeper",
    norm_profile_ids=["rackp.standard.v1"],
)
ok, err = validate(incident_req, "assessment_request.json")
check("ASSESSMENT_REQUEST (two-party) conforms to schema", ok, err)
incident_id = incident_req["incident_id"]

# Phase 2: deposit
dep = c.deposit_fee(incident_id, 10, "USD")
ok, err = validate(dep, "fee_deposit.json")
check("FEE_DEPOSIT conforms to schema", ok, err)

# Phase 3: evidence with external factor claim
ev = c.submit_evidence(
    incident_id,
    REFEREE,
    rec2,
    statement={"summary": "Process log for the window in question",
               "raw_log_reference": f"anchor:{rec2.claim_id}"},
    is_final=True,
    external_factor=("Upstream API outage during the incident window", [rec1.claim_id]),
)
ok, err = validate(ev, "evidence_submission.json")
check("EVIDENCE_SUBMISSION conforms to schema", ok, err)

# Referee-style integrity recomputation (§6.10): SHA-256 of JCS(payload)
recomputed = hashlib.sha256(jcs.canonicalize(ev["payload"])).hexdigest()
check("recomputed payload hash equals stored_hash (anchor consistency)",
      recomputed == ev["verification_info"]["stored_hash"])

# Phase 4: timeout refund. claim_refund returns the embedded FEE_REFUND_RESULT;
# validate the FEE_REFUND_CLAIM the client actually sent (recorded by the stub).
refund_result = c.claim_refund(incident_id)
check("claim_refund returns the embedded FEE_REFUND_RESULT",
      refund_result.get("type") == "FEE_REFUND_RESULT")
refund = transport.keeper(KC).refund_claims[-1]
ok, err = validate(refund, "fee_refund_claim.json")
check("FEE_REFUND_CLAIM conforms to schema", ok, err)
check("refund claim signature verifies", verify_message(pub_b64, refund))

# Transport binding: receipts, rejections, idempotency (TRANSPORT-BINDING.md)
kpub = transport.keeper(KC).identity.public_key_b64url
receipt = transport.send(KC, last_anchor_msg)  # redelivery of identical bytes
ok, err = validate(receipt, "delivery_receipt.json")
check("DELIVERY_RECEIPT conforms to schema", ok, err)
check("receipt signature verifies (signed proof of service)",
      verify_message(kpub, receipt))
check("idempotent redelivery: same receipt, no duplicate state",
      transport.send(KC, last_anchor_msg) == receipt
      and len(transport.keeper(KC).anchors[identity.terminal_id]) == 3)

bad_anchor = dict(last_anchor_msg, sequence_number=99)  # breaks the signature
rejection = transport.send(KC, bad_anchor)
ok, err = validate(rejection, "delivery_rejection.json")
check("DELIVERY_REJECTION conforms to schema", ok, err)
check("tampered anchor rejected with SIGNATURE_INVALID",
      rejection.get("reason") == "SIGNATURE_INVALID")

# Mailbox: party-addressed delivery (Message Delivery, §6)
transport.deliver_to_party(KC, identity.terminal_id,
                           {"type": "EVIDENCE_QUERY_REQUEST", "incident_id": incident_id})
transport.deliver_to_party(KC, identity.terminal_id,
                           {"type": "CONTRIBUTION_RESULT", "incident_id": incident_id})
inbox = c.poll()
check("mailbox poll returns party-addressed messages in order",
      [m["type"] for m in inbox] == ["EVIDENCE_QUERY_REQUEST", "CONTRIBUTION_RESULT"])
# The deployed Keeper's mailbox is a non-destructive read (it never deletes), so a
# repeat poll returns the same held messages; the client is responsible for dedup.
check("mailbox read is non-destructive (matches the deployed Keeper)",
      [m["type"] for m in c.poll()] == ["EVIDENCE_QUERY_REQUEST", "CONTRIBUTION_RESULT"])

# --- published protocol test vectors (schemas/test-vectors) ---------------------

TV_DIR = SCHEMA_DIR / "test-vectors"
tv_jcs = json.loads((TV_DIR / "jcs.json").read_text(encoding="utf-8"))
check("published JCS vectors reproduce",
      all(jcs.canonicalize(v["input"]).decode("utf-8") == v["canonical"]
          for v in tv_jcs["vectors"]))

tv_sig = json.loads((TV_DIR / "signature.json").read_text(encoding="utf-8"))
tv_secret = bytes.fromhex(tv_sig["secret_key_hex"])
check("published vector public key derives from burned secret",
      b64url_encode(ed25519.public_key(tv_secret)) == tv_sig["public_key"])
check("published signature vectors reproduce",
      all(jcs.canonicalize(v["message_body"]).decode("utf-8") == v["canonical"]
          and b64url_encode(
              ed25519.sign(tv_secret, jcs.canonicalize(v["message_body"]))
          ) == v["signature"]
          for v in tv_sig["vectors"]))

tv_ca = json.loads((TV_DIR / "claim_anchor.json").read_text(encoding="utf-8"))
check("published CLAIM_ANCHOR vector: data_hash reproduces",
      hashlib.sha256(
          jcs.canonicalize(tv_ca["anchored_payload"])
      ).hexdigest() == tv_ca["data_hash"])
check("published CLAIM_ANCHOR vector: message verifies with embedded public_key",
      verify_message(tv_ca["message"]["public_key"], tv_ca["message"]))
ok, err = validate(tv_ca["message"], "claim_anchor.json")
check("published CLAIM_ANCHOR vector conforms to schema", ok, err)

# --- summary -------------------------------------------------------------------

failed = [r for r in RESULTS if not r[1]]
print()
print(f"{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed.")
if failed:
    print("FAILED:")
    for name, _, detail in failed:
        print(f"  - {name}: {detail}")
    sys.exit(1)
