# rackp-claimant-krita

A Krita plugin that acts as a RACKP Claimant: it anchors saved files to a Keeper
during normal operation, and files assessments / submits evidence to a Referee
when the user requests one.

Implements [RFC-0001](https://github.com/rackp-io/rackp/blob/main/docs/RFC-0001.md) /
[RFC-0002](https://github.com/rackp-io/rackp/blob/main/docs/RFC-0002.md), spec version **0.1.0-alpha**.

## What it does

- **On each file save**, anchors the file to the configured Keeper: it computes
  `data_hash = SHA-256(JCS({"file_base64": <base64(file_bytes)>}))` and sends a
  signed `CLAIM_ANCHOR`. The base64 content is cached locally so it can be
  attached as evidence later.
- **Every 30 seconds** (if the document changed), anchors the session-log hash to
  build a continuous provenance trail.
- **On assessment request**, files an `ASSESSMENT_REQUEST` to the Referee. The
  rest of the flow is mailbox-driven (see below).

All messages use the baseline single-endpoint HTTP binding
([TRANSPORT-BINDING.md](https://github.com/rackp-io/rackp/blob/main/docs/TRANSPORT-BINDING.md)):
every message is `POST {endpoint}`, acceptance is a signed `DELIVERY_RECEIPT`,
and query-type responses (e.g. `FEE_REFUND_RESULT`, `MAILBOX_RESULT`) are
embedded in that receipt.

## Architecture

The plugin is a thin Krita layer over a Krita-independent protocol core, so the
core can be tested without Krita or Qt.

| Module | Role |
|---|---|
| `jcs.py` | RFC 8785 canonicalization (signing / hashing) |
| `ed25519.py` | Pure-Python Ed25519 (RFC 8032) — no `cryptography` dependency |
| `identity.py` | Keypair, `terminal_id`, message signing |
| `anchoring.py` | `CLAIM_ANCHOR` chain (monotonic sequence, key registration) |
| `transport.py` | `HttpTransport` (the HTTP binding) + `MockTransport` (offline) |
| `claimant.py` | Protocol messages: filing, deposit, evidence, refund |
| `app.py` | Application core: identity/chain persistence, file→anchor cache, assessment lifecycle |
| `plugin.py` | Krita `Extension` + dock, save/timer hooks (imports `krita`) |
| `settings.py`, `log_manager.py`, `assessment_dialog.py` | Persistence, session log, filing dialog |

`__init__.py` registers the plugin only when running inside Krita, so the core
imports cleanly for testing.

## Assessment flow (mailbox-driven)

`ASSESSMENT_REQUEST`, `EVIDENCE_SUBMISSION`, and `CONTRIBUTION_RESULT` are
RFC-0001 messages, so this half is spec-stable regardless of Referee internals:

1. **新規査定依頼** → files an `ASSESSMENT_REQUEST` to the Referee.
2. **進捗を確認** → polls the Claimant's Keeper mailbox (a signed `MAILBOX_QUERY`)
   and reacts: on `EVIDENCE_QUERY_REQUEST` it submits the anchored file as
   `EVIDENCE_SUBMISSION`; on `CONTRIBUTION_RESULT` / `POH_CERTIFICATE` it stores
   the result.
3. **証明書を保存** → writes the received result to disk.

The full loop — anchor, deposit, file, auto-submit evidence on
`EVIDENCE_QUERY_REQUEST`, receive the `POH_CERTIFICATE`, and a silent re-poll
pinning the mailbox dedup — is validated live over real HTTP against both
`rackp-keeper` and `rackp-referee` (see `test_referee_e2e.py` below), including
as a production deployment smoke.

## Known limitations of this reference implementation

### Base64 payload approach

The full file content is embedded as base64 in the `EVIDENCE_SUBMISSION` payload
and cached in the local settings file at save time. This is impractical for
large files (KRA files are ZIP-based and can exceed tens of MB; base64 inflates
by ~33%). It exists solely because Krita's Python addon API does not expose
stroke-level or node-level operation logs — the ideal provenance source. A
native C++ plugin or a Krita core contribution would be required to anchor a
granular operation log instead of per-save file snapshots. **Do not use this
plugin with large image files.**

For production, a Claimant should anchor a content hash (not embed the file) and
provide a separate secure content-retrieval mechanism for the Referee, and
operate at operation-log granularity.

## Tests

Krita-independent; run with any Python 3.10+:

```
python tests/test_keeper_facing.py   # core + transport: anchor/deposit/refund/mailbox
python tests/test_app.py             # app layer: identity persistence, save-anchoring, poll
python tests/test_conformance.py     # crypto + every emitted message against rackp/schemas/
```

These three run offline against an in-memory `MockTransport` by default.
`test_conformance.py` additionally needs `jsonschema` and `referencing`, and
the `rackp` repo checked out as a sibling directory (for the schemas). To
validate the Keeper-facing half against a real Keeper, run a local
`rackp-keeper` (`npx wrangler dev`) and set `RACKP_KEEPER_URL`:

```
RACKP_KEEPER_URL=http://127.0.0.1:8788 python tests/test_keeper_facing.py
RACKP_KEEPER_URL=http://127.0.0.1:8788 python tests/test_app.py
```

`test_referee_e2e.py` drives the full no-Actor PoHI loop over real HTTP
against both a Keeper and a Referee — it is LIVE-only (no mock mode) and needs
both `wrangler dev` instances running with fresh local DBs:

```
(keeper)   cd ../rackp-keeper  && npm run db:migrate:local && npx wrangler dev --port 8788
(referee)  cd ../rackp-referee && npm run db:migrate:local && npx wrangler dev --port 8799 --test-scheduled

RACKP_KEEPER_URL=http://127.0.0.1:8788 RACKP_REFEREE_URL=http://127.0.0.1:8799 \
    python tests/test_referee_e2e.py
```

It also runs against production endpoints as a deployment smoke: without the
`--test-scheduled` hook the Referee's real cron (`*/5`) paces each delivery
leg, so allow ~10-15 minutes end to end.

`test_app.py` uses `RACKP_HOME` (a scratch dir) so it never touches `~/.rackp`.

## Setup

1. Run `install_plugin.bat` (Windows), or copy `rackp_claimant/` and
   `rackp_claimant.desktop` into Krita's `pykrita` folder.
2. Enable the plugin in Krita → Settings → Python Plugin Manager → RACKP Claimant.
3. Configure the Keeper and Referee URLs in the RACKP Claimant dock.

## Contributing

We welcome collaboration from the Krita community, particularly around exposing
stroke-level or node-level operation logs to plugins — which would enable a much
lighter and more meaningful provenance implementation than per-save snapshots.

## License

The source code in this repository is available under the
[RACKP Reference Implementation License](LICENSE) — free to use, modify,
and redistribute, with no patent license granted. Implementing, deploying,
or operating the RACK Protocol, whether with this software or any other
implementation, is governed by the
[RACK Protocol Source-Available License](https://github.com/rackp-io/rackp/blob/main/LICENSE).
Patent pending.
