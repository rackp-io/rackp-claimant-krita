"""Claimant terminal: filing, deposits, evidence, refunds (RFC-0001 Phases 2-4).

Message construction follows the field tables in RFC-0001 §6 and the JSON
schemas.

Query-type sends return the protocol response embedded in the DELIVERY_RECEIPT
(TRANSPORT-BINDING §2): FEE_REFUND_CLAIM -> FEE_REFUND_RESULT.
"""

import uuid

from .anchoring import AnchorLog, DeliveryRejected


class Claimant:
    def __init__(self, identity, keeper_endpoint: str, transport):
        self.identity = identity
        self.keeper_endpoint = keeper_endpoint
        self.transport = transport
        self.anchors = AnchorLog(identity, keeper_endpoint, transport)
        self.incidents: dict[str, dict] = {}

    # --- Phase 1 -----------------------------------------------------------

    def start_session(self, norm_profiles: list[dict]):
        return self.anchors.session_start(norm_profiles)

    def anchor(self, payload: dict, incident_id: str | None = None):
        return self.anchors.anchor(payload, incident_id)

    # --- Phase 2: filing ----------------------------------------------------

    def file_assessment(
        self,
        referee_endpoint: str,
        incident_summary: str,
        incident_timestamp: str,
        actor_id: str | None = None,
        actor_keeper_endpoint: str | None = None,
        norm_profile_ids: list[str] | None = None,
        prior_incident_ids: list[str] | None = None,
    ) -> dict:
        """File an ASSESSMENT_REQUEST. Omit actor_id for a PoHI / no-Actor flow."""
        incident_id = str(uuid.uuid4())
        msg = {
            "type": "ASSESSMENT_REQUEST",
            "incident_id": incident_id,
            "claimant_id": self.identity.terminal_id,
            "keeper_endpoint": self.keeper_endpoint,
            "incident_summary": incident_summary,
            "incident_timestamp": incident_timestamp,
            "timestamp": self.transport.now_iso8601(),
        }
        if actor_id is not None:
            msg["actor_id"] = actor_id
        if actor_keeper_endpoint is not None:
            msg["actor_keeper_endpoint"] = actor_keeper_endpoint
        if norm_profile_ids is not None:
            msg["norm_profile_ids"] = norm_profile_ids
        if prior_incident_ids is not None:
            msg["prior_incident_ids"] = prior_incident_ids
        signed = self.identity.sign_message(msg)
        self.transport.send(referee_endpoint, signed)
        self.incidents[incident_id] = {"request": signed}
        return signed

    def deposit_fee(self, incident_id: str, amount, currency: str) -> dict:
        msg = {
            "type": "FEE_DEPOSIT",
            "incident_id": incident_id,
            "depositor_id": self.identity.terminal_id,
            "amount": amount,
            "currency": currency,
            "timestamp": self.transport.now_iso8601(),
        }
        # Signed (STD-033): the Keeper verifies against depositor_id's
        # registered public_key before crediting escrow.
        signed = self.identity.sign_message(msg)
        self.transport.send(self.keeper_endpoint, signed)
        return signed

    # --- Phase 3: evidence ---------------------------------------------------

    def submit_evidence(
        self,
        incident_id: str,
        referee_endpoint: str,
        anchor_record,
        statement: dict | None = None,
        is_final: bool = False,
        external_factor: tuple[str, list[str]] | None = None,
    ) -> dict:
        """Respond to an EVIDENCE_QUERY_REQUEST with anchored evidence.

        anchor_record: the AnchorRecord whose payload is being submitted.
        external_factor: optional (description, supporting claim_ids) tuple;
        supporting references are mandatory when claiming (STD-023).
        """
        msg = {
            "type": "EVIDENCE_SUBMISSION",
            "incident_id": incident_id,
            "submitter_id": self.identity.terminal_id,
            "payload": anchor_record.payload,
            "verification_info": {
                "keeper_endpoint": self.keeper_endpoint,
                "claim_id": anchor_record.claim_id,
                "sequence_number": anchor_record.sequence_number,
                "stored_hash": anchor_record.data_hash,
            },
            "is_final": is_final,
            "timestamp": self.transport.now_iso8601(),
        }
        if statement is not None:
            msg["statement"] = statement
        if external_factor is not None:
            description, refs = external_factor
            msg["external_factor_claim"] = {
                "claimed": True,
                "description": description,
                "supporting_evidence_refs": refs,
            }
        signed = self.identity.sign_message(msg)
        self.transport.send(referee_endpoint, signed)
        return signed

    # --- Phase 4: timeout refund (STD-028) -----------------------------------

    def claim_refund(self, incident_id: str) -> dict:
        """Send a FEE_REFUND_CLAIM; return the embedded FEE_REFUND_RESULT.

        Raises DeliveryRejected if the Keeper refuses custody of the claim
        (as opposed to a protocol REJECTED, which is a normal embedded result).
        """
        msg = {
            "type": "FEE_REFUND_CLAIM",
            "incident_id": incident_id,
            "depositor_id": self.identity.terminal_id,
            "timestamp": self.transport.now_iso8601(),
        }
        signed = self.identity.sign_message(msg)
        receipt = self.transport.send(self.keeper_endpoint, signed)
        if receipt.get("type") == "DELIVERY_REJECTION":
            raise DeliveryRejected(receipt.get("reason", "UNKNOWN"), receipt.get("detail"))
        return receipt.get("response") or {}

    # --- Mailbox (Message Delivery, §6) ---------------------------------------

    def poll(self, since: str | None = None) -> list[dict]:
        """Messages only. The Keeper's mailbox read is non-destructive; use
        poll_entries() when the caller needs received_at for a since-cursor."""
        return [e["message"] for e in self.poll_entries(since)]

    def poll_entries(self, since: str | None = None) -> list[dict]:
        """MAILBOX_RESULT entries: [{"received_at": ..., "message": ...}]."""
        return self.transport.poll_mailbox(
            self.keeper_endpoint, self.identity.terminal_id, since=since)
