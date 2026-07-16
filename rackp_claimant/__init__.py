"""RACKP Claimant — Krita plugin package.

Krita loads this package; when running inside Krita the plugin (`plugin.py`)
registers its Extension and Dock on import. The protocol core — identity,
anchoring, claimant, transport, jcs, ed25519 — has no Krita dependency and can
be imported and tested standalone (the guard below skips the Krita registration
when `krita` is unavailable).
"""

try:
    import krita  # noqa: F401
except ImportError:
    pass
else:
    from . import plugin  # noqa: F401  # registers the Extension + Dock on import
