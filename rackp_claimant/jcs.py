"""RFC 8785 (JSON Canonicalization Scheme) — documented subset.

The protocol mandates JCS for two purposes:
  - the byte string that Ed25519 signatures cover (all fields except `signature`);
  - the byte string hashed into `data_hash` / verified by the Referee
    (inferred from EVIDENCE_SUBMISSION; see GAP-03).

Subset limitations: number serialization follows ECMAScript rules for integers
and integral floats; non-integral floats are emitted via Python repr, which
matches ECMAScript shortest-round-trip output in the common range but is not
guaranteed at extreme magnitudes (>=1e16). This is no longer just an
implementation assumption: every monetary field this client emits (amount,
*_amount, cancellation_fee, ...) is schema-bounded to <=3 decimal places and
<1e9 (RFC-0001 §6 preamble), and every other numeric field is either an
integer or a 0-1 ratio — all comfortably inside the range this subset handles
exactly.
"""

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def canonicalize(value) -> bytes:
    return _ser(value).encode("utf-8")


def _ser(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return _num(v)
    if isinstance(v, str):
        return _str(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_ser(x) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_str(k) + ":" + _ser(val) for k, val in items) + "}"
    raise TypeError(f"JCS: unsupported type {type(v).__name__}")


def _num(f: float) -> str:
    if f != f or f in (float("inf"), float("-inf")):
        raise ValueError("JCS: non-finite numbers are not permitted")
    if f == int(f) and abs(f) < 1e21:
        return str(int(f))
    return repr(f)


def _str(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)
