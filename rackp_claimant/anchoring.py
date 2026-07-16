"""Continuous anchoring (RFC-0001 §6.1, Phase 1).

The spec calls the anchor sequence a "hash chain", but CLAIM_ANCHOR carries no
linkage field to the previous anchor — only a monotonic sequence_number and the
data_hash of the anchored payload. Chain construction is therefore assumed to be
Keeper-side (GAP-01). This client guarantees monotonic sequence numbers and
records every anchor locally so that EVIDENCE_SUBMISSION can reference them.

data_hash is computed as SHA-256 over the JCS canonicalization of the payload —
not stated in §6.1, inferred from §6.10 where the Referee recomputes exactly that
for verification (GAP-03).

Krita adaptation: the sequence counter and the "registered" flag persist across
plugin restarts (the anchor chain must continue monotonically for the life of
the terminal). The caller seeds `_seq` / `registered` from settings before
anchoring and reads them back afterward. The public key is (re)sent on every
anchor until the Keeper confirms registration with a DELIVERY_RECEIPT, so a
failed sequence-1 delivery does not strand the terminal as UNKNOWN_TERMINAL
(schema-valid: public_key is required at sequence 1 and permitted after).
"""

import hashlib
import uuid
from dataclasses import dataclass, field

from . import jcs


class DeliveryRejected(Exception):
    """A definitive 4xx DELIVERY_REJECTION from the receiver (binding §3)."""

    def __init__(self, reason: str, detail: str | None = None):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass
class AnchorRecord:
    claim_id: str
    sequence_number: int
    data_hash: str
    payload: dict
    incident_id: str | None = None


@dataclass
class AnchorLog:
    identity: object  # TerminalIdentity
    keeper_endpoint: str
    transport: object  # Transport
    _seq: int = 0
    registered: bool = False
    records: list = field(default_factory=list)

    def _base_anchor(self) -> dict:
        self._seq += 1
        msg = {
            "type": "CLAIM_ANCHOR",
            "terminal_id": self.identity.terminal_id,
            "claim_id": str(uuid.uuid4()),
            "sequence_number": self._seq,
            "timestamp": self.transport.now_iso8601(),
        }
        # Required at sequence 1 (§6.1); re-sent until registration is confirmed so a
        # lost first anchor cannot strand the terminal (schema permits it after seq 1).
        if self._seq == 1 or not self.registered:
            msg["public_key"] = self.identity.public_key_b64url
        return msg

    def _deliver(self, signed: dict) -> dict:
        """Send an anchor; on a DELIVERY_RECEIPT mark the terminal registered, on a
        DELIVERY_REJECTION raise. Transport failure (no confirmation) propagates."""
        resp = self.transport.send(self.keeper_endpoint, signed)
        if resp.get("type") == "DELIVERY_REJECTION":
            raise DeliveryRejected(resp.get("reason", "UNKNOWN"), resp.get("detail"))
        self.registered = True
        return resp

    def session_start(self, norm_profiles: list[dict]) -> AnchorRecord:
        """Anchor a SESSION_START declaring the Norm profiles for this session.

        norm_profiles: [{"norm_profile_id": ..., "norm_fetch_url": ...}, ...]
        """
        payload = {"event": "SESSION_START", "norm_profiles": norm_profiles}
        msg = self._base_anchor()
        msg["action_type"] = "SESSION_START"
        msg["norm_profiles"] = norm_profiles
        msg["data_hash"] = hashlib.sha256(jcs.canonicalize(payload)).hexdigest()
        self._deliver(self.identity.sign_message(msg))
        record = AnchorRecord(msg["claim_id"], msg["sequence_number"], msg["data_hash"], payload)
        self.records.append(record)
        return record

    def anchor(self, payload: dict, incident_id: str | None = None) -> AnchorRecord:
        """Anchor arbitrary process/evidence data during normal operation."""
        msg = self._base_anchor()
        if incident_id is not None:
            msg["incident_id"] = incident_id
        msg["data_hash"] = hashlib.sha256(jcs.canonicalize(payload)).hexdigest()
        self._deliver(self.identity.sign_message(msg))
        record = AnchorRecord(
            msg["claim_id"], msg["sequence_number"], msg["data_hash"], payload, incident_id
        )
        self.records.append(record)
        return record
