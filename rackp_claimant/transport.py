"""Transport abstraction and the baseline HTTP binding.

The logical delivery model is RFC-0001 §6 (Message Delivery); the concrete HTTP
binding is docs/TRANSPORT-BINDING.md: every message is POSTed to the receiver's
single endpoint, acceptance is confirmed with a signed DELIVERY_RECEIPT that
binds the message hash and receipt time, query-type requests carry their
protocol response embedded in the receipt's `response` field, definitive
rejections return a 4xx DELIVERY_REJECTION with a reason code, and redelivery of
identical bytes is idempotent.

HttpTransport is the production transport (urllib, no third-party deps).
MockTransport is a binding-conformant in-memory stub for offline tests.
"""

import datetime
import hashlib
import json
import ssl
import urllib.error
import urllib.request
import warnings

from . import jcs
from .identity import TerminalIdentity, verify_message


def message_hash(message: dict) -> str:
    """SHA-256 of the JCS canonicalization of the full message (binding §2)."""
    return hashlib.sha256(jcs.canonicalize(message)).hexdigest()


class Transport:
    def send(self, endpoint: str, message: dict) -> dict:
        """Deliver `message` to `endpoint`.

        Returns a DELIVERY_RECEIPT (accepted; may carry an embedded `response`)
        or a DELIVERY_REJECTION (definitive 4xx rejection). Transport failure —
        no confirmation, e.g. 5xx or timeout — is raised, not returned.
        """
        raise NotImplementedError

    def poll_mailbox(self, keeper_endpoint: str, terminal_id: str,
                     since: str | None = None) -> list[dict]:
        """Fetch party-addressed messages held by the party's own Keeper.

        Mailbox access is implementation-defined (RFC-0001 §6; out of binding
        scope). This client uses the reference Keeper's signed MAILBOX_QUERY,
        whose MAILBOX_RESULT is embedded in the receipt. The Keeper's read is
        NON-destructive, so callers dedup: `since` narrows the query to
        messages received at or after the cursor (the reference Keeper
        compares received_at >= since; the boundary item re-appears and is
        absorbed by message-hash dedup at the caller).

        Returns MAILBOX_RESULT entries: [{"received_at": ..., "message": ...}].
        """
        raise NotImplementedError

    def now_iso8601(self) -> str:
        return (
            datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )


class TransportError(Exception):
    """Delivery could not be confirmed (5xx / network / malformed response)."""


class HttpTransport(Transport):
    """Baseline HTTP binding over urllib (stdlib only).

    `identity` is required to sign the MAILBOX_QUERY used by poll_mailbox; anchor
    and other messages are pre-signed by the caller. DELIVERY_RECEIPT signatures
    are verified on a best-effort basis: the receiver's public_key is fetched
    from `GET {endpoint}` (TRANSPORT-BINDING §1, STD-034) and cached per
    endpoint. An unverifiable receipt (key unavailable, or signature mismatch)
    only warns — per STD-034, it does not undo the delivery the receipt
    confirms; it means that receipt cannot later stand as self-verifying
    evidence.
    """

    def __init__(self, identity: TerminalIdentity | None = None, timeout: float = 15.0,
                 retries: int = 3, ssl_context: ssl.SSLContext | None = None):
        self.identity = identity
        self.timeout = timeout
        self.retries = retries
        self.ssl_context = ssl_context or ssl.create_default_context()
        self._public_key_cache: dict[str, str | None] = {}

    def _fetch_public_key(self, endpoint: str) -> str | None:
        if endpoint in self._public_key_cache:
            return self._public_key_cache[endpoint]
        key = None
        try:
            req = urllib.request.Request(endpoint, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            candidate = body.get("public_key")
            if isinstance(candidate, str):
                key = candidate
        except Exception:
            pass  # leave key=None — treated as unverifiable, not a transport error
        self._public_key_cache[endpoint] = key
        return key

    def _verify_receipt(self, endpoint: str, receipt: dict) -> None:
        public_key = self._fetch_public_key(endpoint)
        if public_key is None:
            warnings.warn(f"DELIVERY_RECEIPT from {endpoint}: no public_key available to verify")
            return
        if not verify_message(public_key, receipt):
            warnings.warn(f"DELIVERY_RECEIPT from {endpoint}: signature did not verify")

    def send(self, endpoint: str, message: dict) -> dict:
        body = json.dumps(message).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": "rackp-claimant-krita/0.2",
            },
            method="POST",
        )
        last_err: Exception | None = None
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                    result = json.loads(resp.read().decode("utf-8"))
                if result.get("type") == "DELIVERY_RECEIPT":
                    self._verify_receipt(endpoint, result)
                return result
            except urllib.error.HTTPError as e:
                if 400 <= e.code < 500:
                    # Definitive rejection (binding §3): return the DELIVERY_REJECTION.
                    try:
                        return json.loads(e.read().decode("utf-8"))
                    except Exception:
                        raise TransportError(f"HTTP {e.code} with unparseable body") from e
                last_err = e  # 5xx: not delivered — retry
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_err = e  # network/timeout: not delivered — retry
            # Backoff between retries (binding §4): 1s, 2s, ...
            if attempt < self.retries - 1:
                import time
                time.sleep(2 ** attempt)
        raise TransportError(f"delivery not confirmed after {self.retries} attempts: {last_err}")

    def poll_mailbox(self, keeper_endpoint: str, terminal_id: str,
                     since: str | None = None) -> list[dict]:
        if self.identity is None:
            raise TransportError("HttpTransport needs an identity to sign MAILBOX_QUERY")
        body = {
            "type": "MAILBOX_QUERY",
            "terminal_id": terminal_id,
            "timestamp": self.now_iso8601(),
        }
        if since is not None:
            body["since"] = since
        query = self.identity.sign_message(body)
        receipt = self.send(keeper_endpoint, query)
        if receipt.get("type") == "DELIVERY_REJECTION":
            raise TransportError(f"mailbox query rejected: {receipt.get('reason')}")
        result = receipt.get("response") or {}
        return list(result.get("messages", []))


# ---------------------------------------------------------------------------
# Offline stub
# ---------------------------------------------------------------------------

class MockTransport(Transport):
    """In-memory transport with a binding-conformant Keeper stub, for offline
    tests. It models the paths this client exercises: sequence-1 key
    registration, signature verification, monotonic sequence enforcement, signed
    DELIVERY_RECEIPTs, reason-coded DELIVERY_REJECTIONs, idempotent redelivery,
    embedded FEE_REFUND_RESULT / MAILBOX_RESULT responses, and a per-party
    mailbox. The authoritative Keeper is rackp-keeper; this is only a test double.
    """

    def __init__(self):
        self.endpoints: dict[str, _MockKeeper] = {}

    def keeper(self, endpoint: str) -> "_MockKeeper":
        if endpoint not in self.endpoints:
            self.endpoints[endpoint] = _MockKeeper()
        return self.endpoints[endpoint]

    def send(self, endpoint: str, message: dict) -> dict:
        return self.keeper(endpoint).receive(message, self.now_iso8601())

    def poll_mailbox(self, keeper_endpoint: str, terminal_id: str,
                     since: str | None = None) -> list[dict]:
        body = {
            "type": "MAILBOX_QUERY", "terminal_id": terminal_id,
            "timestamp": self.now_iso8601(), "signature": "unchecked-in-mock",
        }
        if since is not None:
            body["since"] = since
        receipt = self.send(keeper_endpoint, body)
        return list((receipt.get("response") or {}).get("messages", []))

    def deliver_to_party(self, keeper_endpoint: str, terminal_id: str, message: dict):
        """Simulate a Referee delivering a party-addressed message to Kc."""
        self.keeper(keeper_endpoint).mailboxes.setdefault(terminal_id, []).append(message)


class _MockKeeper:
    def __init__(self):
        self.identity = TerminalIdentity()  # receipts are signed (binding §2)
        self.public_keys: dict[str, str] = {}
        self.anchors: dict[str, list[dict]] = {}
        self.deposits: list[dict] = []
        self.refund_claims: list[dict] = []
        self.mailboxes: dict[str, list[dict]] = {}
        self._acks: dict[str, tuple[int, dict]] = {}  # message_hash -> (status, body) (idempotency §4)

    def _receipt(self, mh: str, received_at: str, response: dict | None = None) -> dict:
        body = {
            "type": "DELIVERY_RECEIPT",
            "received_at": received_at,
            "message_hash": mh,
            "receiver_id": self.identity.terminal_id,
        }
        if response is not None:
            body["response"] = response
        receipt = self.identity.sign_message(body)
        self._acks[mh] = (200, receipt)
        return receipt

    def _reject(self, reason: str, received_at: str, mh: str, detail: str | None = None) -> dict:
        rejection = {
            "type": "DELIVERY_REJECTION",
            "reason": reason,
            "received_at": received_at,
            "receiver_id": self.identity.terminal_id,
        }
        if detail is not None:
            rejection["detail"] = detail
        self._acks[mh] = (400, rejection)
        return rejection

    def receive(self, message: dict, received_at: str) -> dict:
        mh = message_hash(message)
        if mh in self._acks:
            return self._acks[mh][1]  # idempotent redelivery (binding §4)

        mtype = message.get("type")
        if mtype == "CLAIM_ANCHOR":
            tid = message["terminal_id"]
            seq = message["sequence_number"]
            chain = self.anchors.setdefault(tid, [])
            if "public_key" in message:
                self.public_keys.setdefault(tid, message["public_key"])
            if tid not in self.public_keys:
                return self._reject("UNKNOWN_TERMINAL", received_at, mh)
            if not verify_message(self.public_keys[tid], message):
                return self._reject("SIGNATURE_INVALID", received_at, mh)
            if chain and seq <= chain[-1]["sequence_number"]:
                return self._reject("SEQUENCE_CONFLICT", received_at, mh)
            chain.append(message)
            return self._receipt(mh, received_at)

        if mtype == "FEE_DEPOSIT":
            self.deposits.append(message)
            return self._receipt(mh, received_at)

        if mtype == "FEE_REFUND_CLAIM":
            # The stub acknowledges custody and embeds a REJECTED result (no elapsed
            # deadline in-memory); the real Keeper validates the STD-028 timer.
            self.refund_claims.append(message)
            return self._receipt(mh, received_at, response={
                "type": "FEE_REFUND_RESULT",
                "incident_id": message["incident_id"],
                "depositor_id": message["depositor_id"],
                "status": "REJECTED",
                "currency": "USD",
                "rejection_reason": "DEADLINE_NOT_ELAPSED",
                "timestamp": received_at,
            })

        if mtype == "MAILBOX_QUERY":
            # Non-destructive read, matching the deployed Keeper (it SELECTs, never
            # deletes). A client dedups via `since` or by tracking processed messages.
            held = self.mailboxes.get(message["terminal_id"], [])
            return self._receipt(mh, received_at, response={
                "type": "MAILBOX_RESULT",
                "messages": [{"received_at": received_at, "message": m} for m in held],
                "count": len(held),
                "timestamp": received_at,
            })

        return self._receipt(mh, received_at)
