# FINCO Radar — Migration, Coexistence, and Measured Rollback Runbook

## 1. Coexistence Boundary (Implemented)
- **Model Host (`Finco-Protocol/FincoProtocol`, coexistence branch `arch/radar-service-boundary-20261122`):**
  - Introduces `FINCO_MOUNT_RADAR` (default `"1"` — zero behavior change on deploy).
  - Setting `FINCO_MOUNT_RADAR=0` omits all Radar/Yield mounts and achieves zero `finco_radar` and zero `finco_yield` imports at startup.
  - Exposes fail-closed `POST /internal/v1/auth/introspect` (`finco.internal.auth.introspect.v1`, private loopback only) validating `finco_session` and `finco_demo` cookies and returning authoritative server-side `entitlement_decisions`.
- **Radar Host (`Finco-Protocol/Radar`, `radar_service.app:app`):**
  - Runs as an independent systemd service (`deploy/systemd/finco-radar.service`) on `127.0.0.1:8010`.
  - Four independent collector families (`r_live_collector_v1`, `tokenized_market_collector_v1`, `yield_collector_v1`, `yield_alert_automation_v1`) run via `/opt/finco_radar/.venv/bin/python` (prod) and `/opt/finco_radar_staging/.venv/bin/python` (staging), each guarded by `flock -n -E 75` to prevent dual writers.

## 2. Staged Cutover Sequence (Owner-Approved)
1. Deploy standalone Radar wheel (`finco_evidence_envelope-0.1.0` + `finco_radar-0.2.0[server]`) to staging on `127.0.0.1:8010` with `/etc/finco/radar.env` (never committed).
2. Verify `/health`, `/ready`, `/radar`, `/yield`, `/api/v1/crypto/*`, `/api/v1.1/radar/*`, and cross-process auth introspection (`finco_session` + `finco_demo`).
3. Switch nginx candidate config (`deploy/nginx/radar_gateway_candidate.conf`, validated with `nginx -t`) to route verified Radar/Crypto/Yield locations to `127.0.0.1:8010` while keeping `/internal/` blocked (`403`) and Model routes on `127.0.0.1:8000`.
4. After staging/prod soak, set `FINCO_MOUNT_RADAR=0` on Model host.

## 3. Measured Rollback Procedure (Verified Locally)
If any regression occurs after gateway cutover:
1. Revert nginx locations for `/radar*`, `/yield*`, `/crypto*`, `/api/v1/crypto/*`, `/api/v1.1/radar/*` back to `127.0.0.1:8000` (`nginx -t && systemctl reload nginx`).
2. Set `FINCO_MOUNT_RADAR=1` on Model host and restart `finco-web.service`.
3. **Measured Recovery Time (Two-Host Live Rehearsal, `two_host_and_rollback_v2_proof.json`):** `6.920s` wall-clock from `FINCO_MOUNT_RADAR=1` restart to `GET /radar -> 200` on Model host.
4. Keep legacy integrated Radar code intact on Model `main` until post-cutover soak completes and separate owner retirement approval is granted.
