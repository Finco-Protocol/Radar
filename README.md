# FINCO Radar — Standalone Radar / Crypto / Yield Product (Option B)

Independent repository for **FINCO Radar** (`finco_radar`), **FINCO Yield** (`finco_yield`), and the standalone **Radar Service Host** (`radar_service`), separated from `Finco-Protocol/FincoProtocol` (which remains the FINCO Financial Model product).

## Architecture & Shared Contract
- **Shared Contract:** `packages/finco-evidence-envelope` (`finco-evidence-envelope==0.1.0`) — pure-stdlib `EvidenceEnvelope` v1 canonical JSON & payload-only SHA-256 digest (`finco_protocol.verification.envelope`), extracted verbatim from `FincoProtocol@707e68b2`.
- **Auth & Entitlements:** Fail-closed HTTP introspection against the Model host (`POST /internal/v1/auth/introspect`, cookies `finco_session` + `finco_demo` matching `app/auth.py`). Zero shared `FINCO_SECRET_KEY`, zero Model DB access.
- **Read-Only Bridge:** `GET /api/v1.1/radar/bridge-contract` and `GET /api/v1.1/radar/bridge/model-keys` consume Model public verification artifacts read-only.
- **Collectors (4 independent systemd families):** `radar_service.rwa.r_live_collect`, `radar_service.rwa.tokenized_collect`, `finco_yield.collect_live`, `finco_yield.evaluate_alerts` — all guarded by `flock -n -E 75`.

## Reproducible Isolated Wheel Build & Test (Matches CI Verbatim)

```bash
python3 -m build --wheel --outdir dist packages/finco-evidence-envelope
python3 -m build --wheel --outdir dist .

python3 -m venv /tmp/radar-ci-venv
/tmp/radar-ci-venv/bin/pip install --find-links dist \
  dist/finco_evidence_envelope-0.1.0-py3-none-any.whl \
  "dist/finco_radar-0.2.0-py3-none-any.whl[test,server]"
/tmp/radar-ci-venv/bin/pip check

mkdir -p /tmp/radar-isolated-tests/finco_radar/terminal/static
cp -R tests docs deploy PROVENANCE_FROM_FINCOPROTOCOL.json PROVENANCE_ADAPTATIONS_V2.json pyproject.toml /tmp/radar-isolated-tests/
cp finco_radar/terminal/static/radar_terminal.js /tmp/radar-isolated-tests/finco_radar/terminal/static/radar_terminal.js

cd /tmp/radar-isolated-tests
env -u PYTHONPATH /tmp/radar-ci-venv/bin/python -m pytest -v tests/
```

## Running the Standalone Service
```bash
FINCO_MODEL_INTERNAL_AUTH_URL=http://127.0.0.1:8000 \
FINCO_INTERNAL_AUTH_INTROSPECT_TOKEN=<shared-loopback-token> \
/tmp/radar-ci-venv/bin/uvicorn radar_service.app:app --host 127.0.0.1 --port 8010
```
For deterministic offline test fixtures (never for production), set `FINCO_RADAR_OFFLINE_FIXTURE=1`.
