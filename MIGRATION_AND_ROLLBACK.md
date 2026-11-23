# FINCO Radar — Deployment, Coexistence, and Rollback Runbook

> **Deployment status:** Documentation & rehearsal artifact only. Existing Model Radar remains enabled by default (`FINCO_MOUNT_RADAR=1`) until a separately approved production cutover.

## 1. Coexistence Authority (Accepted Model `main`)
- **Financial Model Host (`Finco-Protocol/FincoProtocol` `main` @ `d4c1ed03f52b072f639f873b976e7714d423341a`, PRs #476 & #475 merged):**
  - `FINCO_MOUNT_RADAR` defaults to `"1"` (zero behavior change until cutover).
  - `FINCO_MOUNT_RADAR=0` omits all Radar/Yield mounts and boots with zero `finco_radar` / `finco_yield` imports while preserving all Model-owned institutional endpoints.
  - Exposes fail-closed `POST /internal/v1/auth/introspect` (`finco.internal.auth.introspect.v1`, loopback/private only) validating `finco_session` and `finco_demo` cookies and returning authoritative server-side `entitlement_decisions`.
- **Standalone Radar Host (`Finco-Protocol/Radar`, `radar_service.app:app`):**
  - Independent systemd service (`deploy/systemd/finco-radar.service`) listening on `127.0.0.1:8010`.
  - No shared `FINCO_SECRET_KEY` and no direct Model database access.

## 2. Canonical Paths & Persistent Storage
| Purpose | Canonical Path |
| --- | --- |
| Application install root & venv | `/opt/finco_radar` (`/opt/finco_radar/.venv`) |
| Runtime environment file (`0600`, `finco:finco`) | `/etc/finco/radar.env` (template: `deploy/radar.env.example`) |
| Radar state directory | `/var/lib/finco/radar` |
| Yield state directory | `/var/lib/finco/yield` |
| R-LIVE snapshots DB | `R_LIVE_SNAPSHOT_DB_PATH=/var/lib/finco/radar/r_live_snapshots.db` |
| R-LIVE intelligence ledger DB | `RADAR_BNB_INTELLIGENCE_DB_PATH=/var/lib/finco/radar/radar_bnb_intelligence.db` |
| Tokenized venues DB | `FINCO_VENUE_DB_PATH=/var/lib/finco/radar/venues_market_observations.db` |
| Radar crypto alerts DB | `FINCO_RADAR_ALERTS_DB_PATH=/var/lib/finco/radar/radar_crypto_alerts.db` |
| Yield watchlist & alerts DB | `FINCO_DB_PATH=/var/lib/finco/radar/yield_watchlist_alerts.db` |
| Yield snapshot & history | `FINCO_YIELD_SNAPSHOT_PATH=/var/lib/finco/yield/current_snapshot.json`, `FINCO_YIELD_HISTORY_PATH=/var/lib/finco/yield/yield_history.jsonl` |

> Never point `FINCO_DB_PATH` at Model's `/var/lib/finco/finco.db`.

## 3. Installation Procedure
1. Provision canonical directories and isolated virtualenv:
   ```bash
   sudo install -d -o finco -g finco -m 0750 /opt/finco_radar /var/lib/finco/radar /var/lib/finco/yield
   sudo -u finco python3.12 -m venv /opt/finco_radar/.venv
   sudo -u finco /opt/finco_radar/.venv/bin/pip install --no-deps dist/finco_evidence_envelope-0.1.0-py3-none-any.whl
   sudo -u finco /opt/finco_radar/.venv/bin/pip install --find-links dist "dist/finco_radar-0.2.0-py3-none-any.whl[server]"
   sudo -u finco /opt/finco_radar/.venv/bin/pip check
   ```
2. Populate `/etc/finco/radar.env` (mode `0600`, owner `finco:finco`) from `deploy/radar.env.example`:
   - Set `FINCO_ENV=production` (note: offline-fixture mode is strictly disabled in `staging`/`production`).
   - Set `FINCO_MODEL_INTERNAL_AUTH_URL=http://127.0.0.1:8000` and the private shared `FINCO_INTERNAL_AUTH_INTROSPECT_TOKEN` (must match Model host).
   - Set `FINCO_RADAR_CSRF_SECRET` (random >= 32 chars, independent of Model's `FINCO_SECRET_KEY`).
   - Confirm all persistent DB/JSONL paths under `/var/lib/finco/radar` and `/var/lib/finco/yield`.
3. Install systemd unit `deploy/systemd/finco-radar.service` to `/etc/systemd/system/finco-radar.service`, then `systemctl daemon-reload && systemctl enable --now finco-radar.service`.
4. Configure collectors (disabled by default until explicitly enabled in `/etc/finco/*.env`, all using `/opt/finco_radar/.venv/bin/python` and `flock -n -E 75` single-writer locks):
   - `deploy/r_live_collector_v1/finco-r-live-collector.{service,timer}`
   - `deploy/tokenized_market_collector_v1/finco-tokenized-market-collector.{service,timer}`
   - `deploy/yield_collector_v1/finco-yield-collector.{service,timer}`
   - `deploy/yield_alert_automation_v1/finco-yield-alert-evaluator.{service,timer}`

## 4. Gateway Configuration (`nginx`)
- Candidate config: `deploy/nginx/radar_gateway_candidate.conf` (validate with `sudo nginx -t`).
- Hard blocks `/internal/` with HTTP `403` so Model internal auth introspection is never publicly reachable.
- Routes verified Radar/Yield/Crypto locations (`/radar*`, `/yield*`, `/crypto*`, `/api/v1/radar/*`, `/api/v1/crypto/tokenized*`, `/api/v1/crypto/yield*`, `/api/v1.1/radar/r-live/*`, `/api/v1.1/radar/rwa-basis*`, `/api/v1.1/radar/bridge*`) to `127.0.0.1:8010`.
- Default `/` remains on Model upstream `127.0.0.1:8000`.

## 5. Health & Integration Smoke Checks
1. Local service health & readiness:
   ```bash
   curl -fsS http://127.0.0.1:8010/health
   curl -fsS http://127.0.0.1:8010/ready
   ```
   Confirm `status == "ready"`, `auth_authority_configured == true`, `snapshot_mode != "OFFLINE_FIXTURE"`, and HTTP `503` on any corrupt SQLite store.
2. Auth & fail-closed checks:
   - Unauthenticated `GET /api/v1/radar/session-context` -> HTTP `401`.
   - Valid `finco_session` / `finco_demo` cookie -> HTTP `200` with canonical `entitlement_decisions` from Model.
   - Public gateway `POST /internal/v1/auth/introspect` -> HTTP `403`.
   - Model unavailable -> fail-closed HTTP `503` on protected session introspection.
3. Product surfaces:
   - `GET /radar`, `GET /yield`, `GET /api/v1/radar/assets`, `GET /api/v1/crypto/tokenized`, `GET /api/v1/crypto/yield`, `GET /api/v1.1/radar/r-live/assets`, `GET /api/v1.1/radar/rwa-basis`.

## 6. Rollback Procedure
If any regression occurs after a separately approved gateway cutover:
1. Revert nginx Radar/Yield/Crypto locations back to `http://finco_model_upstream` (`127.0.0.1:8000`), then run `sudo nginx -t && sudo systemctl reload nginx`.
2. Ensure `FINCO_MOUNT_RADAR=1` on the Model host and restart `finco-web.service`.
3. Verify `GET /radar` -> HTTP `200` on Model host (`6.920s` measured recovery in two-host rehearsal).
4. Stop `finco-radar.service` and collector timers if needed while preserving `/var/lib/finco/radar` and `/var/lib/finco/yield` for post-mortem inspection.
5. Keep legacy integrated Radar code intact on Model `main` until post-cutover soak completes and separate owner retirement approval is granted.
