"""Pure-Python Ed25519 (RFC 8032).

Implemented from RFC 8032 with no crypto-library dependency, because Krita's
bundled Python cannot be assumed to ship `cryptography`. Validated against the
RFC 8032 test vectors and the protocol's schemas/test-vectors/. Signing is
per-anchor (one save / one 30s tick), so the pure-Python speed is acceptable
here; a native library should be preferred where one is available.
"""

import hashlib

_p = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    return pow(x, _p - 2, _p)


_d = -121665 * _inv(121666) % _p
_By = 4 * _inv(5) % _p


def _recover_x(y: int, sign: int) -> int:
    if y >= _p:
        raise ValueError("invalid point encoding")
    x2 = (y * y - 1) * _inv(_d * y * y + 1) % _p
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * pow(2, (_p - 1) // 4, _p) % _p
    if (x * x - x2) % _p != 0:
        raise ValueError("invalid point")
    if x == 0 and sign == 1:
        raise ValueError("invalid point")
    if x % 2 != sign:
        x = _p - x
    return x


_Bx = _recover_x(_By, 0)
_B = (_Bx, _By, 1, _Bx * _By % _p)  # extended homogeneous coordinates
_IDENTITY = (0, 1, 1, 0)


def _add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % _p
    B = (Y1 + X1) * (Y2 + X2) % _p
    C = T1 * 2 * _d * T2 % _p
    D = Z1 * 2 * Z2 % _p
    E = B - A
    F = D - C
    G = D + C
    H = B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul(s: int, P):
    Q = _IDENTITY
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _encode_point(P) -> bytes:
    X, Y, Z, _T = P
    zinv = _inv(Z)
    x = X * zinv % _p
    y = Y * zinv % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decode_point(b: bytes):
    if len(b) != 32:
        raise ValueError("invalid point length")
    enc = int.from_bytes(b, "little")
    sign = enc >> 255
    y = enc & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return (x, y, 1, x * y % _p)


def _point_equal(P, Q) -> bool:
    X1, Y1, Z1, _ = P
    X2, Y2, Z2, _ = Q
    return (X1 * Z2 - X2 * Z1) % _p == 0 and (Y1 * Z2 - Y2 * Z1) % _p == 0


def _secret_expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("secret must be 32 bytes")
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(secret: bytes) -> bytes:
    a, _ = _secret_expand(secret)
    return _encode_point(_mul(a, _B))


def sign(secret: bytes, message: bytes) -> bytes:
    a, prefix = _secret_expand(secret)
    A = _encode_point(_mul(a, _B))
    r = int.from_bytes(_sha512(prefix + message), "little") % _L
    Rs = _encode_point(_mul(r, _B))
    h = int.from_bytes(_sha512(Rs + A + message), "little") % _L
    s = (r + h * a) % _L
    return Rs + int.to_bytes(s, 32, "little")


def verify(pub: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64 or len(pub) != 32:
        return False
    try:
        A = _decode_point(pub)
        R = _decode_point(signature[:32])
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(_sha512(signature[:32] + pub + message), "little") % _L
    return _point_equal(_mul(s, _B), _add(R, _mul(h, A)))
