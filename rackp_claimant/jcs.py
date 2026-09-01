"""RFC 8785 (JSON Canonicalization Scheme).

The protocol mandates JCS for two purposes:
  - the byte string that Ed25519 signatures cover (all fields except `signature`);
  - the byte string hashed into `data_hash` / verified by the Referee
    (inferred from EVIDENCE_SUBMISSION; see GAP-03).

RFC 8785 defers number formatting to ECMAScript's Number::toString, which
`_num` implements directly rather than deferring to Python's `repr`: the two
agree on the significant digits (both produce the shortest decimal that reads
back to the same float) but disagree on where decimal notation gives way to
exponential — Python below 1e-4, ECMAScript below 1e-6 — and on how the
exponent is written. A value in that band would canonicalize to different
bytes here than at the Referee, which is a live risk: `data_hash` is taken
over application-supplied payloads, not just this client's own schema-bounded
fields.
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
    sign = "-" if f < 0 else ""
    digits, n = _shortest_digits(abs(f))
    return sign + _format_ecmascript(digits, n)


def _shortest_digits(f: float) -> tuple:
    """The shortest round-trip decimal digits of `f` (f > 0, non-integral, finite),
    as (digits, n) with digits[0] != '0' and f == int(digits) * 10**(n - len(digits)).

    `repr` already computes the digit string ECMAScript would too — both
    implement shortest round-trip decimal, which is uniquely determined by the
    float, not by the algorithm that finds it. Only its layout (decimal point
    placement, exponential threshold, exponent spelling) is Python's own, so it
    is parsed back into (digits, n) here and laid out again in `_format_ecmascript`.
    """
    r = repr(f)
    if "e" in r:
        mantissa, exp_str = r.split("e")
        exp = int(exp_str)
        int_part, _, frac_part = mantissa.partition(".")
        digits = int_part + frac_part
        n = exp + 1
    else:
        int_part, _, frac_part = r.partition(".")
        combined = int_part + frac_part
        point_pos = len(int_part)
        stripped = combined.lstrip("0")
        n = point_pos - (len(combined) - len(stripped))
        digits = stripped
    digits = digits.rstrip("0") or "0"
    return digits, n


def _format_ecmascript(digits: str, n: int) -> str:
    """ECMA-262 Number::toString layout for a positive value with digit string
    `digits` (no leading/trailing zero) and decimal-point position `n`, i.e.
    value == int(digits) * 10**(n - len(digits))."""
    k = len(digits)
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * -n + digits
    exp = n - 1
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return mantissa + "e" + ("+" if exp >= 0 else "-") + str(abs(exp))


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
