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
    (
        "numbers: below Python's exponential threshold but above ECMAScript's (rackp-claimant-krita#1)",
        {"n": [0.0001, 0.00001, 0.000012345, 1.5e-5]},
    ),
    ("numbers: below both thresholds, exponent has no leading zero", {"n": [1e-7, -1.5e-5]}),
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

# --- 4. proof_hash: the nested and top-level exclusion rules (rackp#18) ---------

# CONTRIBUTION_RESULT (schemas/contribution_result.json): proof_hash lives at
# assessment.certification.proof_hash -- excluding it means removing that one key
# two levels down, not touching anything else, and not touching the object it sits
# in (certification keeps cert_id/issue_date/cert_url either way). signature is
# excluded too, but it is simply never added until after proof_hash is computed,
# same as the CLAIM_ANCHOR vector above.
contribution_result_without_proof_hash = {
    "type": "CONTRIBUTION_RESULT",
    "network": "TESTNET",
    "rackp_version": "0.2.0-alpha",
    "incident_id": "44444444-4444-4444-8444-444444444444",
    "referee_id": "55555555-5555-4555-8555-555555555555",
    "referee_reputation_snapshot": {
        "total_assessments": 1,
        "snapshot_timestamp": "2026-01-01T00:00:00Z",
    },
    "assessment": {
        "factual_findings": "Both parties' anchor chains verified against submitted evidence.",
        "fault": {
            "actor_fault": 0.5,
            "claimant_fault": 0.5,
            "external_factor": 0.0,
            "confidence": "HIGH",
        },
        "evidence_sufficiency": {
            "assessment_status": "DEFINITIVE",
            "actor_coverage": "MEDIUM",
            "claimant_coverage": "MEDIUM",
        },
        "fee_compliance": {
            "actor_fee_status": "DEPOSITED",
            "claimant_fee_status": "DEPOSITED",
            "fee_snapshot": {
                "total_amount": 100.0,
                "claimant_expected": 100.0,
                "actor_expected": 100.0,
                "currency": "USD",
            },
        },
        "actor_participation": {"status": "NOT_APPLICABLE"},
        "provenance_score": {
            "actor_provenance": {"human_ratio": 0.2, "ai_ratio": 0.8},
            "claimant_provenance": {"human_ratio": 0.1, "ai_ratio": 0.9},
            "confidence_level": "HIGH",
        },
        # String array is the pre-rackp#15 shape (CONTRIBUTION_RESULT.norms_used has
        # nowhere yet to carry a document hash on the fault side). Regenerate this
        # vector if rackp#15 gives it POH_CERTIFICATE's {profile_id, ...} shape.
        "norms_used": ["rackp.standard.v1"],
        "detailed_report": {
            "report_url": "https://rackp.example/reports/44444444-4444-4444-8444-444444444444",
            "report_hash": "a" * 64,
        },
        "certification": {
            "cert_id": "CERT-44444444-20260101000000-0001",
            "issue_date": "2026-01-01T00:00:00Z",
            "cert_url": "https://rackp.example/verify/CERT-44444444-20260101000000-0001",
            # proof_hash filled in below, once the body it commits to is complete.
        },
    },
    "evidence_provenance": "actor=VERIFIED, claimant=VERIFIED",
    "additional_appeal_limit_datetime": "2026-01-04T00:00:00Z",
    "prior_assessment_count": 0,
    "timestamp": "2026-01-01T00:00:00Z",
}
contribution_result_canonical_without_proof_hash = jcs.canonicalize(contribution_result_without_proof_hash)
contribution_result_proof_hash = hashlib.sha256(contribution_result_canonical_without_proof_hash).hexdigest()

contribution_result = json.loads(contribution_result_canonical_without_proof_hash)
contribution_result["assessment"]["certification"]["proof_hash"] = contribution_result_proof_hash
contribution_result_signing_body = jcs.canonicalize(contribution_result)
contribution_result_signature = b64url_encode(ed25519.sign(BURNED_SECRET, contribution_result_signing_body))
contribution_result["signature"] = contribution_result_signature

# POH_CERTIFICATE (schemas/poh_certificate.json): proof_hash is a top-level field,
# sitting beside signature rather than nested under anything -- the same shape as
# every other signed message in this protocol, unlike CONTRIBUTION_RESULT's.
poh_certificate_without_proof_hash = {
    "type": "POH_CERTIFICATE",
    "rackp_version": "0.2.0-alpha",
    "cert_id": "66666666-6666-4666-8666-666666666666",
    "issue_date": "2026-01-01T00:00:00Z",
    "referee_id": "55555555-5555-4555-8555-555555555555",
    "subject_terminal_id": "11111111-1111-4111-8111-111111111111",
    "anchor_range": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:05:00Z"},
    "provenance": {"human_ratio": 1.0, "ai_ratio": 0.0, "confidence_level": "HIGH"},
    "norms_used": [
        {
            "profile_id": "rackp.standard.v1",
            "applied_document_hash": "c" * 64,
            "declared_document_hash": "d" * 64,
        }
    ],
    "keeper": {
        "keeper_id": "77777777-7777-4777-8777-777777777777",
        "keeper_public_key": b64url_encode(PUBLIC_KEY),
    },
    "subject_data_hash": "e" * 64,
    "cert_url": "https://rackp.example/phi/66666666-6666-4666-8666-666666666666",
}
poh_certificate_canonical_without_proof_hash = jcs.canonicalize(poh_certificate_without_proof_hash)
poh_certificate_proof_hash = hashlib.sha256(poh_certificate_canonical_without_proof_hash).hexdigest()

poh_certificate = json.loads(poh_certificate_canonical_without_proof_hash)
poh_certificate["proof_hash"] = poh_certificate_proof_hash
poh_certificate_signing_body = jcs.canonicalize(poh_certificate)
poh_certificate_signature = b64url_encode(ed25519.sign(BURNED_SECRET, poh_certificate_signing_body))
poh_certificate["signature"] = poh_certificate_signature

write("proof_hash.json", {
    "description": "proof_hash known-answer vectors (rackp#18). Each field is SHA-256 (lowercase hex) of the JCS canonical form of the artifact with proof_hash itself absent -- not null, not an empty string, simply not a key in the object being canonicalized -- and, for 'contribution_result', with signature also absent (it is only added afterward, once proof_hash is known). 'contribution_result' exercises a NESTED exclusion (assessment.certification.proof_hash, two levels down, with the rest of 'certification' and 'assessment' otherwise present); 'poh_certificate' exercises a top-level exclusion (proof_hash sits beside signature, not nested). An implementation conforms if it reproduces 'proof_hash' from '*_without_proof_hash', and 'signature' by then signing the canonical form of the artifact WITH proof_hash filled in (the full document, still minus signature).",
    "secret_key_hex": BURNED_SECRET.hex(),
    "public_key": b64url_encode(PUBLIC_KEY),
    "vectors": [
        {
            "description": "CONTRIBUTION_RESULT: nested exclusion at assessment.certification.proof_hash",
            "artifact_without_proof_hash": contribution_result_without_proof_hash,
            "canonical_without_proof_hash": contribution_result_canonical_without_proof_hash.decode("utf-8"),
            "proof_hash": contribution_result_proof_hash,
            "signature": contribution_result_signature,
            "artifact": contribution_result,
        },
        {
            "description": "POH_CERTIFICATE: top-level exclusion, proof_hash beside signature",
            "artifact_without_proof_hash": poh_certificate_without_proof_hash,
            "canonical_without_proof_hash": poh_certificate_canonical_without_proof_hash.decode("utf-8"),
            "proof_hash": poh_certificate_proof_hash,
            "signature": poh_certificate_signature,
            "artifact": poh_certificate,
        },
    ],
})
