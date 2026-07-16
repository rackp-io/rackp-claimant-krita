"""Terminal identity: keypair, terminal_id, and message signing.

RFC-0001 common.json: signature = Ed25519 over the JCS canonicalization of the
message body (all fields except `signature`), Base64url-encoded.

Base64url padding is unspecified in the protocol (GAP-04); this implementation
emits unpadded Base64url and accepts both on verification.
"""

import base64
import os
import uuid

from . import ed25519, jcs


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


class TerminalIdentity:
    def __init__(self, secret: bytes | None = None, terminal_id: str | None = None):
        self.secret = secret if secret is not None else os.urandom(32)
        self.terminal_id = terminal_id if terminal_id is not None else str(uuid.uuid4())
        self.public_key_bytes = ed25519.public_key(self.secret)

    @property
    def public_key_b64url(self) -> str:
        return b64url_encode(self.public_key_bytes)

    def sign_message(self, message: dict) -> dict:
        """Return a copy of `message` with `signature` populated."""
        body = {k: v for k, v in message.items() if k != "signature"}
        sig = ed25519.sign(self.secret, jcs.canonicalize(body))
        signed = dict(message)
        signed["signature"] = b64url_encode(sig)
        return signed


def verify_message(public_key_b64url: str, message: dict) -> bool:
    """Independent verification path — what a Keeper does per RFC-0001 §4.4."""
    sig_text = message.get("signature")
    if not isinstance(sig_text, str):
        return False
    body = {k: v for k, v in message.items() if k != "signature"}
    try:
        pub = b64url_decode(public_key_b64url)
        sig = b64url_decode(sig_text)
    except Exception:
        return False
    return ed25519.verify(pub, jcs.canonicalize(body), sig)
