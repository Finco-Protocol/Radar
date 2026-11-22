# Staging/Production Gateway Routing, Collector Safety & Rollback

## 1. Public Route Split (`deploy/nginx/radar_gateway_candidate.conf`)
- **Routed to `FincoRadar` (`127.0.0.1:8010`):**
  - `/radar`, `/radar/`
  - `/crypto`, `/crypto/`
  - `/api/v1/radar/`
  - `/api/v1/crypto/`
  - `/api/v1.1/radar/`
  - `/api/v1.1/rwa-basis/`
- **Kept on `FincoProtocol` Model (`127.0.0.1:8000`):**
  - `/v2/`, `/library`, `/verify`, `/.well-known/finco/keys.json`
  - `/api/v1/model/`
  - `/api/v1.1/runs/`
  - **NEVER** proxy broad `/api/v1/` or `/api/v1.1/` to Radar.

## 2. Preventing Double Collector Execution During Dual-Run
- The 4 systemd collectors (`r_live_collector_v1`, `tokenized_market_collector_v1`, `yield_collector_v1`, `yield_alert_automation_v1`) must run from **at most one host/unit** at a time.
- During rehearsal and staging dual-run, keep write-side collector timers disabled on the secondary host and set `FINCO_RLIVE_WARMING_ENABLED=0` on `FincoProtocol` once the dedicated Radar collector is active.

## 3. Rollback Procedure (<60s Rehearsal Target)
1. Switch nginx location blocks for `/radar*`, `/crypto*`, `/api/v1/radar/*`, `/api/v1/crypto/*`, `/api/v1.1/radar/*`, `/api/v1.1/rwa-basis/*` back to `FincoProtocol` (`127.0.0.1:8000`) with `FINCO_MOUNT_RADAR=1`.
2. Reload nginx (`nginx -t && systemctl reload nginx`).
3. Stop `finco-radar.service` and secondary collector timers.
4. Verify `/radar`, `/api/v1/model/*`, and `/v2/*` return HTTP 200 on `FincoProtocol`.
