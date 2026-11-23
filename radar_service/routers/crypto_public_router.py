"""Standalone Crypto Tokenized, Yield Market API, and /crypto Overview + Durable Alerts router.

Correction C runtime parity:
- Uses REAL VenueMarketStore APIs (`get_latest_for_underlying`, `get_window_for_underlying`,
  `get_latest_reference_for_underlying`, `count`) — never silent `except Exception: return []`.
- Distinguishes absent/unpopulated store vs corrupt SQLite DB (`503 VENUE_STORE_CORRUPT`)
  vs populated observations & reference basis.
- Uses REAL YieldHistoryStore (`FINCO_YIELD_HISTORY_PATH`) + `read_rows_by_uid` +
  `build_market_view` on `/api/v1/crypto/yield` (proving nonempty `history_available: True`
  when persisted history exists, `503` on corrupt store, `False` when unpopulated).
- Rejects unsafe `/tmp` alerts DB default in staging/production (`FINCO_ENV` check).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from finco_radar.venues.seed_loader import load_seed
from finco_radar.venues.store import VenueMarketStore
from finco_yield.history import YieldHistoryStore
from finco_yield.market import build_market_view, read_rows_by_uid
from finco_yield.registry import load_bundled_registry
from radar_service.auth_client import IntrospectionUnavailableError
from radar_service.entitlements import (
    Decision,
    evaluate_resource_access,
    generate_csrf_token,
    resolve_request_session,
    validate_csrf_token,
    wallet_context_for_session,
)

router = APIRouter(tags=["crypto-api-and-ui"])
_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))
_TEMPLATES.env.autoescape = True


def _is_prod_or_staging() -> bool:
    return os.getenv("FINCO_ENV", "").strip().lower() in ("prod", "production", "staging")


def _alerts_db_path() -> Path:
    raw = os.getenv("FINCO_RADAR_ALERTS_DB_PATH", "").strip()
    if raw:
        return Path(raw)
    if _is_prod_or_staging():
        raise HTTPException(status_code=503, detail="FINCO_RADAR_ALERTS_DB_PATH_NOT_CONFIGURED")
    return Path("/tmp/finco_radar_alerts.db")


def _connect_alerts_db() -> sqlite3.Connection:
    p = _alerts_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS radar_crypto_alerts (
            alert_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def _serialize_obs(obs: Any) -> dict[str, Any]:
    if hasattr(obs, "to_dict"):
        return obs.to_dict()
    ts = getattr(obs, "ts", None)
    price = getattr(obs, "price", None)
    ref_price = getattr(obs, "reference_price", None)
    basis_bps = getattr(obs, "basis_bps", None)
    status = getattr(obs, "observation_status", None)
    return {
        "canonical_asset_id": getattr(obs, "canonical_asset_id", None),
        "venue_id": getattr(obs, "venue_id", None),
        "instrument_id": getattr(obs, "instrument_id", None),
        "instrument_type": getattr(obs, "instrument_type", None),
        "mid_price_usd": str(price) if price is not None else None,
        "reference_price_usd": str(ref_price) if ref_price is not None else None,
        "basis_bps": str(basis_bps) if basis_bps is not None else None,
        "observed_at": ts.isoformat() if hasattr(ts, "isoformat") else str(ts or ""),
        "status": status.value if hasattr(status, "value") else str(status or ""),
    }


def _open_venue_store() -> VenueMarketStore | None:
    db_path = os.getenv("FINCO_VENUE_DB_PATH", "").strip()
    if not db_path or not Path(db_path).is_file():
        return None
    try:
        store = VenueMarketStore(db_path)
        # Probe readability immediately so corrupt SQLite fails closed with 503
        store.count()
        return store
    except sqlite3.DatabaseError as exc:
        raise HTTPException(status_code=503, detail=f"VENUE_STORE_CORRUPT: {exc}") from exc


def _read_venue_latest_and_window(canonical_asset_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any] | None]:
    store = _open_venue_store()
    if store is None:
        return [], [], None
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=7)
    try:
        latest_row = store.get_latest_for_underlying(canonical_asset_id)
        window_rows = store.get_window_for_underlying(canonical_asset_id, since=since, until=now)
        ref_row = store.get_latest_reference_for_underlying(canonical_asset_id)
    except sqlite3.DatabaseError as exc:
        raise HTTPException(status_code=503, detail=f"VENUE_STORE_CORRUPT: {exc}") from exc
    venue_latest_by_id: dict[str, Any] = {}
    eq_ref_row: Any = None
    for row in window_rows:
        if getattr(row, "instrument_type", None) == "equity_reference":
            if eq_ref_row is None or str(getattr(row, "ts", "")) >= str(getattr(eq_ref_row, "ts", "")):
                eq_ref_row = row
            continue
        vid = getattr(row, "venue_id", None) or getattr(row, "instrument_id", "")
        prev = venue_latest_by_id.get(vid)
        if prev is None or str(getattr(row, "ts", "")) >= str(getattr(prev, "ts", "")):
            venue_latest_by_id[vid] = row
    if venue_latest_by_id:
        latest_list = [_serialize_obs(r) for r in venue_latest_by_id.values()]
    elif latest_row is not None and getattr(latest_row, "instrument_type", None) != "equity_reference":
        latest_list = [_serialize_obs(latest_row)]
    else:
        latest_list = []
    chosen_ref = eq_ref_row if eq_ref_row is not None else ref_row
    return (
        latest_list,
        [_serialize_obs(r) for r in window_rows],
        _serialize_obs(chosen_ref) if chosen_ref is not None else None,
    )


async def _require_crypto_api(request: Request, resource: str = "crypto.api") -> dict[str, Any]:
    """Enforce canonical crypto.api AND resource-specific access via authoritative evaluator."""
    try:
        session = resolve_request_session(request)
    except IntrospectionUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "ENTITLEMENT_AUTHORITY_UNAVAILABLE", "resource": resource},
        ) from exc

    wallet = wallet_context_for_session(session)
    api_dec = await evaluate_resource_access("crypto.api", wallet)
    if api_dec.decision is Decision.DENY:
        status = 503 if not api_dec.authority_available else 403
        raise HTTPException(
            status_code=status,
            detail={"error": "CRYPTO_API_ACCESS_DENIED", "resource": "crypto.api", "reason": api_dec.reason_code},
        )

    res_dec = api_dec if resource == "crypto.api" else await evaluate_resource_access(resource, wallet)
    if res_dec.decision is Decision.DENY:
        status = 503 if not res_dec.authority_available else 403
        raise HTTPException(
            status_code=status,
            detail={"error": "CRYPTO_RESOURCE_ACCESS_DENIED", "resource": resource, "reason": res_dec.reason_code},
        )
    return {
        "api_decision": api_dec.decision.value,
        "decision": res_dec.decision.value,
        "reason": res_dec.reason_code,
        "session": session,
    }


def _find_tokenized(canonical_asset_id: str) -> list[dict[str, Any]]:
    seed = load_seed()
    reps = seed.get("representations", [])
    needle = canonical_asset_id.lower()
    return [
        r for r in reps
        if needle in (
            str(r.get("canonical_asset_id", "")).lower(),
            str(r.get("representation_symbol", "")).lower(),
            str(r.get("underlying_symbol", "")).lower(),
        )
    ]


@router.get("/api/v1/crypto/tokenized")
async def list_tokenized_assets(request: Request) -> JSONResponse:
    access = await _require_crypto_api(request, "tokenized.basic")
    seed = load_seed()
    reps = seed.get("representations", [])
    store = _open_venue_store()
    obs_count = store.count() if store is not None else 0
    return JSONResponse({
        "schema": "finco.crypto.tokenized.v1",
        "as_of": datetime.now(timezone.utc).isoformat(),
        "access": {"api_decision": access["api_decision"], "decision": access["decision"], "reason": access["reason"]},
        "history_available": obs_count > 0,
        "observation_count": obs_count,
        "data_origin": "VENUE_STORE" if obs_count > 0 else "SEED_REGISTRY",
        "count": len(reps),
        "items": reps,
    }, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}")
async def get_tokenized_asset(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "tokenized.basic")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    underlying = str(matches[0].get("underlying_symbol") or canonical_asset_id)
    latest, _, ref = _read_venue_latest_and_window(underlying)
    return JSONResponse({
        "schema": "finco.crypto.tokenized.detail.v1",
        "as_of": datetime.now(timezone.utc).isoformat(),
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "underlying_symbol": underlying,
        "venues": matches,
        "reference_observation": ref,
        "live_observation_count": len(latest),
        "observations": latest,
    }, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}/dislocations")
async def get_tokenized_dislocations(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "tokenized.dislocation")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    underlying = str(matches[0].get("underlying_symbol") or canonical_asset_id)
    latest, _, ref = _read_venue_latest_and_window(underlying)
    dislocations = []
    ref_price_str = (ref.get("reference_price_usd") or ref.get("mid_price_usd")) if ref else None
    if ref_price_str:
        from decimal import Decimal
        ref_p = Decimal(ref_price_str)
        if ref_p > 0:
            for row in latest:
                if row.get("mid_price_usd"):
                    vp = Decimal(row["mid_price_usd"])
                    bps = ((vp - ref_p) / ref_p) * Decimal("10000")
                    dislocations.append({
                        "venue_id": row["venue_id"],
                        "venue_price_usd": str(vp),
                        "reference_price_usd": str(ref_p),
                        "basis_bps": str(bps.quantize(Decimal("0.01"))),
                        "observed_at": row["observed_at"],
                    })
    return JSONResponse({
        "schema": "finco.crypto.tokenized.dislocations.v1",
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "state": "AVAILABLE" if dislocations else ("OBSERVATIONS_WITHOUT_REFERENCE" if latest else "NO_LIVE_OBSERVATIONS"),
        "dislocations": dislocations,
    }, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}/history")
async def get_tokenized_history(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "tokenized.history")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    underlying = str(matches[0].get("underlying_symbol") or canonical_asset_id)
    _, window, _ = _read_venue_latest_and_window(underlying)
    return JSONResponse({
        "schema": "finco.crypto.tokenized.history.v1",
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "history_available": bool(window),
        "points": window,
    }, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}/integrity")
async def get_tokenized_integrity(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "tokenized.basic")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    underlying = str(matches[0].get("underlying_symbol") or canonical_asset_id)
    latest, _, ref = _read_venue_latest_and_window(underlying)
    return JSONResponse({
        "schema": "finco.crypto.tokenized.integrity.v1",
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "venue_count": len(matches),
        "observed_count": len(latest),
        "reference_present": ref is not None,
        "integrity_state": "OBSERVED_AND_BOUND" if latest else "REGISTRY_BOUND",
    }, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}/signals")
async def get_tokenized_signals(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "tokenized.dislocation")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    underlying = str(matches[0].get("underlying_symbol") or canonical_asset_id)
    latest, _, ref = _read_venue_latest_and_window(underlying)
    signals = []
    if ref and latest:
        signals.append({
            "signal_type": "VENUE_REFERENCE_COMPARABLE",
            "underlying_symbol": underlying,
            "venue_count": len(latest),
            "reference_observed_at": ref["observed_at"],
        })
    return JSONResponse({
        "schema": "finco.crypto.tokenized.signals.v1",
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "signals_active": bool(signals),
        "signals": signals,
    }, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/crypto/yield")
async def list_crypto_yield(request: Request) -> JSONResponse:
    access = await _require_crypto_api(request, "crypto.api")
    reg = load_bundled_registry()
    opps = reg.all()
    now = datetime.now(timezone.utc)

    hist_path_raw = os.getenv("FINCO_YIELD_HISTORY_PATH", "").strip()
    rows_by_uid: dict[str, Any] = {}
    history_available = False
    if hist_path_raw and Path(hist_path_raw).is_file():
        try:
            hstore = YieldHistoryStore(Path(hist_path_raw))
            rows_by_uid = read_rows_by_uid(hstore)
            history_available = any(len(v) > 0 for v in rows_by_uid.values())
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"YIELD_HISTORY_CORRUPT: {exc}") from exc
        market_view = build_market_view(hstore, reg, as_of=now, rows_by_uid=rows_by_uid)
    else:
        market_view = build_market_view(None, reg, as_of=now, rows_by_uid={})

    items = [
        {
            "opportunity_uid": o.uid,
            "name": o.name,
            "protocol": o.protocol,
            "asset": o.underlying_symbol,
            "chain_id": o.chain_id,
            "data_origin": o.data_origin,
            "history_points": len(rows_by_uid.get(o.uid, ())),
        }
        for o in opps
    ]
    return JSONResponse({
        "schema": "finco.crypto.yield.v1",
        "as_of": now.isoformat(),
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "market_summary": {
            "pool_count": len(opps),
            "mover_count": len(getattr(market_view, "movers", ())),
            "history_available": history_available,
        },
        "count": len(items),
        "items": items,
    }, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/crypto/yield/{canonical_id}")
async def get_crypto_yield(request: Request, canonical_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "crypto.api")
    opps = load_bundled_registry().all()
    for o in opps:
        if o.uid == canonical_id:
            return JSONResponse({
                "schema": "finco.crypto.yield.detail.v1",
                "access": {"decision": access["decision"], "reason": access["reason"]},
                "opportunity_uid": o.uid,
                "name": o.name,
                "protocol": o.protocol,
                "asset": o.underlying_symbol,
                "chain_id": o.chain_id,
                "data_origin": o.data_origin,
            }, headers={"Cache-Control": "no-store"})
    raise HTTPException(status_code=404, detail="Unknown yield opportunity")


# ── /crypto UI & SQLite-Persisted Owner-Scoped Alerts ─────────────────────────

def _require_authenticated_csrf(request: Request) -> dict[str, Any]:
    try:
        session = resolve_request_session(request)
    except IntrospectionUnavailableError as exc:
        raise HTTPException(status_code=503, detail="AUTH_AUTHORITY_UNAVAILABLE") from exc
    if not session:
        raise HTTPException(status_code=401, detail="AUTHENTICATION_REQUIRED")
    csrf = request.headers.get("X-CSRF-Token") or request.headers.get("x-csrf-token")
    if not validate_csrf_token(str(session.get("user_id", "")), csrf):
        raise HTTPException(status_code=403, detail="CSRF_TOKEN_INVALID")
    return session


@router.get("/crypto", response_class=HTMLResponse)
async def crypto_overview(request: Request) -> HTMLResponse:
    try:
        session = resolve_request_session(request)
    except IntrospectionUnavailableError:
        session = None
    sid = str(session.get("user_id", "")) if session else "anonymous"
    csrf_token = generate_csrf_token(sid)
    opps = load_bundled_registry().all()
    seed = load_seed()
    unread = 0
    if session:
        with _connect_alerts_db() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM radar_crypto_alerts WHERE owner_id = ? AND is_read = 0",
                (sid,),
            ).fetchone()
            unread = int(row["c"]) if row else 0
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<title>FINCO Crypto Overview</title></head>"
        f"<body data-csrf='{csrf_token}' data-authenticated='{str(bool(session)).lower()}'>"
        "<header><h1>FINCO Crypto Terminal</h1>"
        "<nav><a href='/crypto'>Overview</a> | <a href='/yield'>Yield</a> | <a href='/radar'>Radar</a></nav></header>"
        f"<main><section><h2>Market Coverage</h2><p>Tokenized venues: {len(seed.get('representations', []))}</p>"
        f"<p>Yield opportunities: {len(opps)}</p><p>Unread alerts: {unread}</p></section></main></body></html>"
    )
    return HTMLResponse(content=html, status_code=200, headers={"Cache-Control": "no-store"})


@router.get("/crypto/alerts.json")
async def crypto_alerts_json(request: Request) -> JSONResponse:
    try:
        session = resolve_request_session(request)
    except IntrospectionUnavailableError as exc:
        raise HTTPException(status_code=503, detail="AUTH_AUTHORITY_UNAVAILABLE") from exc
    if not session:
        raise HTTPException(status_code=401, detail="AUTHENTICATION_REQUIRED")
    owner_id = str(session["user_id"])
    with _connect_alerts_db() as conn:
        rows = conn.execute(
            "SELECT alert_id, title, severity, is_read, created_at FROM radar_crypto_alerts "
            "WHERE owner_id = ? ORDER BY created_at DESC",
            (owner_id,),
        ).fetchall()
    alerts = [
        {
            "alert_id": r["alert_id"],
            "title": r["title"],
            "severity": r["severity"],
            "read": bool(r["is_read"]),
            "created_at": r["created_at"],
        }
        for r in rows
    ]
    unread_count = sum(1 for a in alerts if not a["read"])
    return JSONResponse({
        "schema": "finco.crypto.alerts.v1",
        "owner_id": owner_id,
        "unread_count": unread_count,
        "alerts": alerts,
    }, headers={"Cache-Control": "no-store"})


@router.post("/crypto/alerts/refresh")
async def crypto_alerts_refresh(request: Request) -> JSONResponse:
    session = _require_authenticated_csrf(request)
    owner_id = str(session["user_id"])
    with _connect_alerts_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM radar_crypto_alerts WHERE owner_id = ?",
            (owner_id,),
        ).fetchone()
        total = int(row["c"]) if row else 0
    return JSONResponse({"status": "ok", "owner_id": owner_id, "alert_count": total})


@router.post("/crypto/alerts/read-all")
async def crypto_alerts_read_all(request: Request) -> JSONResponse:
    session = _require_authenticated_csrf(request)
    owner_id = str(session["user_id"])
    with _connect_alerts_db() as conn:
        cur = conn.execute(
            "UPDATE radar_crypto_alerts SET is_read = 1 WHERE owner_id = ? AND is_read = 0",
            (owner_id,),
        )
        conn.commit()
        updated = cur.rowcount
    return JSONResponse({"status": "ok", "owner_id": owner_id, "marked_read": updated})


@router.post("/crypto/alerts/{alert_id}/read")
async def crypto_alert_mark_read(request: Request, alert_id: str) -> JSONResponse:
    session = _require_authenticated_csrf(request)
    owner_id = str(session["user_id"])
    with _connect_alerts_db() as conn:
        cur = conn.execute(
            "UPDATE radar_crypto_alerts SET is_read = 1 WHERE alert_id = ? AND owner_id = ?",
            (alert_id, owner_id),
        )
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="ALERT_NOT_FOUND")
    return JSONResponse({"status": "ok", "owner_id": owner_id, "alert_id": alert_id, "read": True})
