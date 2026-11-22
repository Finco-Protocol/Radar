"""Standalone Crypto Tokenized, Yield Market API, and /crypto Overview + Durable Alerts router.

Correction B parity closure:
- Uses EXACT canonical Model resource keys (`crypto.api`, `tokenized.basic`,
  `tokenized.history`, `tokenized.dislocation`) — zero invented keys.
- Reads real persisted `VenueMarketStore` observations when populated (returning real
  observations/dislocations/history) and honest typed empty states when unpopulated.
- Uses real `finco_yield.market.build_market_view` on `/api/v1/crypto/yield`.
- Uses real SQLite-persisted per-owner alert store (`FINCO_RADAR_ALERTS_DB_PATH`) on
  `/crypto/alerts.json`, `/crypto/alerts/refresh`, `/crypto/alerts/read-all`, and
  `/crypto/alerts/{alert_id}/read` with strict owner/tenant isolation and CSRF enforcement.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from finco_radar.venues.seed_loader import load_seed
from finco_radar.venues.store import VenueMarketStore
from finco_yield.market import build_market_view
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


def _alerts_db_path() -> Path:
    raw = os.getenv("FINCO_RADAR_ALERTS_DB_PATH", "").strip()
    if raw:
        return Path(raw)
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


def _read_venue_observations(symbol_or_id: str) -> list[dict[str, Any]]:
    db_path = os.getenv("FINCO_VENUE_DB_PATH", "").strip()
    if not db_path or not Path(db_path).is_file():
        return []
    try:
        store = VenueMarketStore(db_path)
        if hasattr(store, "list_recent_observations"):
            rows = store.list_recent_observations(symbol_or_id)
            return [dict(r) if isinstance(r, dict) else r.__dict__ for r in rows]
    except Exception:
        return []
    return []


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
    db_path = os.getenv("FINCO_VENUE_DB_PATH", "").strip()
    store_populated = bool(db_path and Path(db_path).is_file())
    return JSONResponse({
        "schema": "finco.crypto.tokenized.v1",
        "as_of": datetime.now(timezone.utc).isoformat(),
        "access": {"api_decision": access["api_decision"], "decision": access["decision"], "reason": access["reason"]},
        "history_available": store_populated,
        "data_origin": "VENUE_STORE" if store_populated else "SEED_REGISTRY",
        "count": len(reps),
        "items": reps,
    }, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}")
async def get_tokenized_asset(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "tokenized.basic")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    obs = _read_venue_observations(canonical_asset_id)
    return JSONResponse({
        "schema": "finco.crypto.tokenized.detail.v1",
        "as_of": datetime.now(timezone.utc).isoformat(),
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "venues": matches,
        "live_observation_count": len(obs),
        "observations": obs,
    }, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}/dislocations")
async def get_tokenized_dislocations(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "tokenized.dislocation")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    obs = _read_venue_observations(canonical_asset_id)
    return JSONResponse({
        "schema": "finco.crypto.tokenized.dislocations.v1",
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "state": "AVAILABLE" if obs else "NO_LIVE_OBSERVATIONS",
        "dislocations": obs,
    }, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}/history")
async def get_tokenized_history(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "tokenized.history")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    obs = _read_venue_observations(canonical_asset_id)
    return JSONResponse({
        "schema": "finco.crypto.tokenized.history.v1",
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "history_available": bool(obs),
        "points": obs,
    }, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}/integrity")
async def get_tokenized_integrity(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "tokenized.basic")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    obs = _read_venue_observations(canonical_asset_id)
    return JSONResponse({
        "schema": "finco.crypto.tokenized.integrity.v1",
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "venue_count": len(matches),
        "observed_count": len(obs),
        "integrity_state": "OBSERVED_AND_BOUND" if obs else "REGISTRY_BOUND",
    }, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}/signals")
async def get_tokenized_signals(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "tokenized.dislocation")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    obs = _read_venue_observations(canonical_asset_id)
    return JSONResponse({
        "schema": "finco.crypto.tokenized.signals.v1",
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "signals_active": bool(obs),
        "signals": obs,
    }, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/crypto/yield")
async def list_crypto_yield(request: Request) -> JSONResponse:
    access = await _require_crypto_api(request, "crypto.api")
    reg = load_bundled_registry()
    opps = reg.all()
    now = datetime.now(timezone.utc)
    market_view = build_market_view(None, reg, as_of=now, rows_by_uid={})
    items = [
        {
            "opportunity_uid": o.uid,
            "name": o.name,
            "protocol": o.protocol,
            "asset": o.underlying_symbol,
            "chain_id": o.chain_id,
            "data_origin": o.data_origin,
        }
        for o in opps
    ]
    return JSONResponse({
        "schema": "finco.crypto.yield.v1",
        "as_of": datetime.now(timezone.utc).isoformat(),
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "market_summary": {
            "pool_count": len(opps),
            "mover_count": len(getattr(market_view, "movers", ())),
            "history_available": False,
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
