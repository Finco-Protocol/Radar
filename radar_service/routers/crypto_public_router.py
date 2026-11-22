"""Standalone Crypto Tokenized, Yield API, and /crypto Overview + Alerts router.

Restores access-controlled Crypto API endpoints (matching FincoProtocol app/api/v1/crypto_router.py
access semantics) and /crypto UI + CSRF-protected alert endpoints:
- GET /api/v1/crypto/tokenized
- GET /api/v1/crypto/tokenized/{canonical_asset_id}
- GET /api/v1/crypto/tokenized/{canonical_asset_id}/dislocations
- GET /api/v1/crypto/tokenized/{canonical_asset_id}/history
- GET /api/v1/crypto/tokenized/{canonical_asset_id}/integrity
- GET /api/v1/crypto/tokenized/{canonical_asset_id}/signals
- GET /api/v1/crypto/yield
- GET /api/v1/crypto/yield/{canonical_id}
- GET /crypto
- GET /crypto/alerts.json
- POST /crypto/alerts/refresh (auth + CSRF required)
- POST /crypto/alerts/read-all (auth + CSRF required)
- POST /crypto/alerts/{alert_id}/read (auth + CSRF required)
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from finco_radar.venues.seed_loader import load_seed
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


async def _require_crypto_api(request: Request, resource: str = "crypto.api") -> dict[str, Any]:
    """Enforce canonical crypto.api resource access via authoritative evaluator (fail-closed)."""
    try:
        session = resolve_request_session(request)
    except IntrospectionUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "ENTITLEMENT_AUTHORITY_UNAVAILABLE", "resource": resource},
        ) from exc

    wallet = wallet_context_for_session(session)
    decision = await evaluate_resource_access(resource, wallet)
    if decision.decision is Decision.DENY:
        status = 503 if not decision.authority_available else 403
        raise HTTPException(
            status_code=status,
            detail={
                "error": "CRYPTO_API_ACCESS_DENIED",
                "resource": resource,
                "reason": decision.reason_code,
            },
        )
    return {
        "decision": decision.decision.value,
        "reason": decision.reason_code,
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
    access = await _require_crypto_api(request, "crypto.api")
    seed = load_seed()
    reps = seed.get("representations", [])
    return JSONResponse({
        "schema": "finco.crypto.tokenized.v1",
        "as_of": datetime.now(timezone.utc).isoformat(),
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "data_origin": "SEED_REGISTRY",
        "count": len(reps),
        "items": reps,
    })


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}")
async def get_tokenized_asset(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "crypto.tokenized.detail")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    return JSONResponse({
        "schema": "finco.crypto.tokenized.detail.v1",
        "as_of": datetime.now(timezone.utc).isoformat(),
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "venues": matches,
    })


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}/dislocations")
async def get_tokenized_dislocations(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "crypto.tokenized.detail")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    return JSONResponse({
        "schema": "finco.crypto.tokenized.dislocations.v1",
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "state": "NO_LIVE_OBSERVATIONS",
        "dislocations": [],
    })


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}/history")
async def get_tokenized_history(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "crypto.tokenized.history")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    return JSONResponse({
        "schema": "finco.crypto.tokenized.history.v1",
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "history_available": False,
        "points": [],
    })


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}/integrity")
async def get_tokenized_integrity(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "crypto.tokenized.detail")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    return JSONResponse({
        "schema": "finco.crypto.tokenized.integrity.v1",
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "venue_count": len(matches),
        "integrity_state": "REGISTRY_BOUND",
    })


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}/signals")
async def get_tokenized_signals(request: Request, canonical_asset_id: str) -> JSONResponse:
    access = await _require_crypto_api(request, "crypto.tokenized.signals")
    matches = _find_tokenized(canonical_asset_id)
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    return JSONResponse({
        "schema": "finco.crypto.tokenized.signals.v1",
        "access": {"decision": access["decision"], "reason": access["reason"]},
        "canonical_asset_id": canonical_asset_id,
        "signals_active": False,
        "signals": [],
    })


@router.get("/api/v1/crypto/yield")
async def list_crypto_yield(request: Request) -> JSONResponse:
    access = await _require_crypto_api(request, "crypto.api")
    opps = load_bundled_registry().all()
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
        "count": len(items),
        "items": items,
    })


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
            })
    raise HTTPException(status_code=404, detail="Unknown yield opportunity")


# ── /crypto UI & CSRF-protected Alerts endpoints ──────────────────────────────

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
    html = (
        "<!doctype html><html><head><title>FINCO Crypto Overview</title></head>"
        f"<body data-csrf='{csrf_token}'><h1>FINCO Crypto</h1>"
        "<nav><a href='/yield'>Yield</a> | <a href='/radar'>Radar</a></nav></body></html>"
    )
    return HTMLResponse(content=html, status_code=200)


@router.get("/crypto/alerts.json")
async def crypto_alerts_json(request: Request) -> JSONResponse:
    try:
        session = resolve_request_session(request)
    except IntrospectionUnavailableError as exc:
        raise HTTPException(status_code=503, detail="AUTH_AUTHORITY_UNAVAILABLE") from exc
    if not session:
        raise HTTPException(status_code=401, detail="AUTHENTICATION_REQUIRED")
    return JSONResponse({
        "schema": "finco.crypto.alerts.v1",
        "owner_id": session["user_id"],
        "unread_count": 0,
        "alerts": [],
    }, headers={"Cache-Control": "no-store"})


@router.post("/crypto/alerts/refresh")
async def crypto_alerts_refresh(request: Request) -> JSONResponse:
    session = _require_authenticated_csrf(request)
    return JSONResponse({"status": "ok", "owner_id": session["user_id"], "refreshed": 0})


@router.post("/crypto/alerts/read-all")
async def crypto_alerts_read_all(request: Request) -> JSONResponse:
    session = _require_authenticated_csrf(request)
    return JSONResponse({"status": "ok", "owner_id": session["user_id"], "marked_read": 0})


@router.post("/crypto/alerts/{alert_id}/read")
async def crypto_alert_mark_read(request: Request, alert_id: str) -> JSONResponse:
    session = _require_authenticated_csrf(request)
    return JSONResponse({"status": "ok", "owner_id": session["user_id"], "alert_id": alert_id, "read": True})
