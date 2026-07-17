"""Application layer: bridges persistent settings and the protocol core.

This is the plugin's Krita-independent seam. The Krita UI (plugin.py) drives it
from background threads; the offline tests drive it directly. It owns identity
persistence, anchor-chain continuity, the file->anchor cache, and the assessment
lifecycle, delegating all protocol/transport behaviour to the core Claimant.

Assessment lifecycle (RFC-0001 Phases 2-4, all over the single-endpoint binding):
  file_assessment  -> ASSESSMENT_REQUEST to the Referee endpoint
  poll             -> drains the Claimant's Keeper mailbox and reacts:
                        EVIDENCE_QUERY_REQUEST -> EVIDENCE_SUBMISSION (the anchored file)
                        CONTRIBUTION_RESULT / POH_CERTIFICATE -> stored as the result
The Referee-facing half is spec-stable (these are RFC-0001 messages); it awaits
the Referee reference rewrite for live end-to-end testing.
"""
import base64
import hashlib
import os

from . import settings
from .identity import TerminalIdentity, b64url_encode, b64url_decode
from .anchoring import AnchorRecord
from .transport import HttpTransport, message_hash
from .claimant import Claimant

# Processed-message ledger cap: the mailbox read is non-destructive, so the
# app remembers what it already handled; old hashes age out once the since
# cursor has moved far past them.
_PROCESSED_CAP = 500


class ClaimantApp:
    def __init__(self, config: dict | None = None, transport=None):
        self.config = config if config is not None else settings.load()
        self._ensure_identity()
        secret = b64url_decode(self.config["secret_b64url"])
        self.identity = TerminalIdentity(secret=secret, terminal_id=self.config["terminal_id"])
        self.transport = transport or HttpTransport(identity=self.identity)
        self.claimant = Claimant(self.identity, self.config["keeper_url"], self.transport)
        # Seed anchor-chain continuity from persisted state.
        self.claimant.anchors._seq = self.config.get("sequence_number", 0)
        self.claimant.anchors.registered = self.config.get("registered", False)

    # --- identity / persistence -------------------------------------------

    def _ensure_identity(self):
        if self.config.get("terminal_id") and self.config.get("secret_b64url"):
            return
        ident = TerminalIdentity()
        self.config["terminal_id"] = ident.terminal_id
        self.config["secret_b64url"] = b64url_encode(ident.secret)
        self.config["public_key"] = ident.public_key_b64url
        settings.save(self.config)

    def _persist_chain(self):
        self.config["sequence_number"] = self.claimant.anchors._seq
        self.config["registered"] = self.claimant.anchors.registered
        settings.save(self.config)

    @property
    def terminal_id(self) -> str:
        return self.identity.terminal_id

    def norm_profiles(self) -> list[dict]:
        return [{
            "norm_profile_id": self.config["norm_profile_id"],
            "norm_fetch_url": self.config["norm_fetch_url"],
        }]

    # --- Phase 1: anchoring -------------------------------------------------

    def session_start(self) -> AnchorRecord:
        rec = self.claimant.start_session(self.norm_profiles())
        self._persist_chain()
        return rec

    def anchor_log(self, log_hash: str) -> AnchorRecord:
        """Anchor a pre-computed session-log hash (payload references the log)."""
        rec = self.claimant.anchor({"event": "session_log", "log_sha256": log_hash})
        self._persist_chain()
        return rec

    def anchor_file(self, filepath: str) -> AnchorRecord:
        """Anchor a saved file. The anchored payload is {"file_base64": <content>},
        so the Referee can recompute data_hash = SHA-256(JCS(payload)) from the
        EVIDENCE_SUBMISSION (README documents the base64 approach and its limits).

        The PoHI artifact binding (RFC-0001 §8.4) rides in the same payload:
        subject_data_hash is the SHA-256 of the raw file bytes, so a later
        no-Actor assessment can bind its POH_CERTIFICATE to this exact artifact
        without re-anchoring (the binding must be inside the anchored payload,
        or the evidence hash would no longer match the anchor)."""
        with open(filepath, "rb") as f:
            raw = f.read()
        b64 = base64.b64encode(raw).decode("ascii")
        payload = {
            "file_base64": b64,
            "pohi": {
                "subject_data_hash": hashlib.sha256(raw).hexdigest(),
                "content_id": os.path.basename(filepath),
            },
        }
        rec = self.claimant.anchor(payload)
        self._persist_chain()
        cache = self.config.setdefault("file_anchors", {})
        prev = cache.get(filepath, {})
        cache[filepath] = {
            "claim_id": rec.claim_id,
            "data_hash": rec.data_hash,
            "sequence": rec.sequence_number,
            "timestamp": self.transport.now_iso8601(),
            # The exact anchored payload: evidence must resubmit it verbatim or
            # the Referee's recomputed hash will not match the anchor.
            "payload": payload,
            "file_base64": b64,
            "anchor_count": prev.get("anchor_count", 0) + 1,
        }
        settings.save(self.config)
        return rec

    # --- Phase 2: filing ----------------------------------------------------

    def file_assessment(self, description: str, filepath: str | None,
                        actor_id: str | None = None) -> str:
        """File an ASSESSMENT_REQUEST; return the incident_id. The file's cached
        anchor is stored with the incident so evidence can be submitted when the
        Referee later asks (via the mailbox)."""
        signed = self.claimant.file_assessment(
            referee_endpoint=self.config["referee_url"],
            incident_summary=description,
            incident_timestamp=self.transport.now_iso8601(),
            actor_id=actor_id or None,
            actor_keeper_endpoint=None,
            norm_profile_ids=[self.config["norm_profile_id"]],
        )
        incident_id = signed["incident_id"]
        anchor = self.config.get("file_anchors", {}).get(filepath) if filepath else None
        self.config.setdefault("incidents", {})[incident_id] = {
            "description": description,
            "actor_id": actor_id or None,
            "filepath": filepath,
            "status": "FILED",
            "created_at": signed["timestamp"],
            "anchor": anchor,
            "result": None,
        }
        settings.save(self.config)
        return incident_id

    # --- Phase 3/4: mailbox-driven progress ---------------------------------

    def poll(self) -> list[str]:
        """Drain the Keeper mailbox and react to Referee messages. Returns a list
        of human-readable notes about what happened, for the UI to surface.

        The Keeper's mailbox read is NON-destructive: every poll re-returns held
        messages. Two mechanisms keep processing exactly-once: a `since` cursor
        (the latest received_at seen, sent with the MAILBOX_QUERY) narrows the
        read, and a processed message-hash ledger absorbs the >= boundary
        overlap and any redelivery."""
        notes: list[str] = []
        processed = self.config.setdefault("processed_messages", [])
        seen = set(processed)
        since = self.config.get("mailbox_since")
        latest = since
        for entry in self.claimant.poll_entries(since=since):
            msg = entry.get("message", {})
            received_at = entry.get("received_at")
            if received_at and (latest is None or received_at > latest):
                latest = received_at
            mh = message_hash(msg)
            if mh in seen:
                continue
            seen.add(mh)
            processed.append(mh)
            mtype = msg.get("type")
            incident_id = msg.get("incident_id")
            inc = self.config.get("incidents", {}).get(incident_id) if incident_id else None
            if mtype == "EVIDENCE_QUERY_REQUEST" and inc:
                self._submit_stored_evidence(incident_id, inc)
                notes.append(f"{incident_id[:8]}…: evidence submitted")
            elif mtype == "CONTRIBUTION_RESULT" and inc:
                inc["result"] = msg
                status = (msg.get("assessment", {})
                          .get("evidence_sufficiency", {})
                          .get("assessment_status", "?"))
                inc["status"] = f"ASSESSMENT ({status})"
                notes.append(f"{incident_id[:8]}…: assessment result received")
            elif mtype == "POH_CERTIFICATE":
                # POH_CERTIFICATE carries no incident_id (RFC-0001 §8.4): it is
                # matched by the certified subject and the awaiting PoHI filing.
                got = self._match_pohi_incident(msg)
                if got:
                    notes.append(f"{got[:8]}…: PoHI certificate received")
        del processed[:-_PROCESSED_CAP]
        if latest != since:
            self.config["mailbox_since"] = latest
        settings.save(self.config)
        return notes

    def _match_pohi_incident(self, cert: dict) -> str | None:
        """Attach a POH_CERTIFICATE to the newest no-Actor incident still
        awaiting a result. Returns the incident_id, or None if nothing matches
        (e.g. a certificate for a different terminal)."""
        if cert.get("subject_terminal_id") != self.terminal_id:
            return None
        candidates = [
            (inc.get("created_at", ""), incident_id, inc)
            for incident_id, inc in self.config.get("incidents", {}).items()
            if inc.get("actor_id") is None and inc.get("result") is None
        ]
        if not candidates:
            return None
        _, incident_id, inc = max(candidates)
        inc["result"] = cert
        inc["status"] = "POH_CERTIFICATE"
        return incident_id

    def _submit_stored_evidence(self, incident_id: str, inc: dict):
        anchor = inc.get("anchor")
        if not anchor or "file_base64" not in anchor:
            inc["status"] = "EVIDENCE_UNAVAILABLE"
            settings.save(self.config)
            return
        # The evidence payload must be byte-identical (after JCS) to what was
        # anchored. Newer caches store the exact payload (with the PoHI
        # binding); pre-binding caches only held file_base64.
        payload = anchor.get("payload") or {"file_base64": anchor["file_base64"]}
        record = AnchorRecord(
            claim_id=anchor["claim_id"],
            sequence_number=anchor["sequence"],
            data_hash=anchor["data_hash"],
            payload=payload,
            incident_id=incident_id,
        )
        self.claimant.submit_evidence(
            incident_id=incident_id,
            referee_endpoint=self.config["referee_url"],
            anchor_record=record,
            statement={"summary": inc.get("description", ""),
                       "raw_log_reference": anchor["claim_id"]},
            is_final=True,
        )
        inc["status"] = "EVIDENCE_SUBMITTED"
        settings.save(self.config)
