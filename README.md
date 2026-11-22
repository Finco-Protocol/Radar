# Finco-Protocol/Radar

Standalone FINCO Radar / Crypto / Yield repository extracted under Option B from `Finco-Protocol/FincoProtocol@707e68b290694c57b470f4a112c190abb3d02ac9` (tree `0d4e8961c33e7bab7aa94077ee4fe9b561061ba2`).

## Architecture & Boundaries
- **Owned here:** `finco_radar/` (R0–R12 market/RWA intelligence & terminal), `radar_service/` (standalone FastAPI host, fail-closed auth introspection client, read-only bridge contract), `finco_yield/` (yield intelligence package), `deploy/` (4 systemd collectors + nginx/systemd candidate configs), `docs/radar/`, and standalone tests.
- **Shared verification contract:** `packages/finco-evidence-envelope/` (`finco-evidence-envelope==0.1.0`, pure-stdlib `finco_protocol.verification.envelope` copied byte-for-byte from `FincoProtocol@707e68b2`).
- **Remains in `Finco-Protocol/FincoProtocol` (Model):** `financial_engine/`, `finco_core/`, `domain/`, `tax_reference_registry/`, Model React & legacy workbooks, Model DB/persistence, `app/api/v1/model_router.py`, `app/api/v1_1/run_certificate_public_router.py`, `app/verified/{composer,router}.py`, and session authority (`POST /internal/v1/auth/introspect`).

## Reproducible Local Build & Isolated Wheel Verification
```bash
python3 -m build --wheel --outdir dist packages/finco-evidence-envelope
python3 -m build --wheel --outdir dist .
python3 -m venv .venv-isolated
.venv-isolated/bin/pip install --find-links dist dist/finco_evidence_envelope-0.1.0-py3-none-any.whl dist/finco_radar-0.1.0-py3-none-any.whl pytest==9.0.3
.venv-isolated/bin/pip check
PYTHONPATH= .venv-isolated/bin/python -m pytest -q tests/
```

## Provenance & Cutover Status
- Exact file-by-file Git blob/mode/SHA-256 lineage is recorded in `PROVENANCE_FROM_FINCOPROTOCOL.json`.
- See `MIGRATION_AND_ROLLBACK.md` for staged staging/production rollout, collector lease safety, and `<60s` rollback to `FincoProtocol` (`FINCO_MOUNT_RADAR=1`).
