"""Runnable standalone FINCO Radar / Crypto / Yield FastAPI service host (Option B).

Mounts:
- GET /health, GET /ready (honest dependency, template, registry, and snapshot-mode readiness)
- Authentic finco_radar.terminal.web R6 terminal (/radar, /radar/api/snapshot, /radar/static/*)
- Authentic finco_yield.web router (/yield, /yield/* — all 14 Yield web & API routes)
- Authentic R-LIVE public API (/api/v1.1/radar/r-live/*)
- Authentic RWA-Basis public API (/api/v1.1/radar/rwa-basis*)
- Authentic Crypto Tokenized & Yield APIs (/api/v1/crypto/tokenized*, /api/v1/crypto/yield*)
- GET /api/v1/radar/session-context (strict typed fail-closed Model host introspection;
  cookies match FincoProtocol app/auth.py: finco_session + finco_demo)
- GET /api/v1.1/radar/bridge-contract & GET /api/v1.1/radar/bridge/model-keys (read-only bridge)
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Callable, Optional

from fastapi import Cookie, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from finco_protocol.verification.envelope import build_evidence_envelope
from finco_radar.terminal.contracts import (
    AssetHeader,
    CandidateAuditEntry,
    DisplayValue,
    HistoryPanel,
    LiquidityPanel,
    ReferencePanel,
    SignalPanel,
    TerminalSnapshot,
    TerminalStatus,
)
from finco_radar.terminal.presenter import reconstruct_terminal_digest
from finco_radar.terminal.web import ROOT as TERMINAL_ROOT, create_radar_app
from finco_yield.registry import load_bundled_registry
from finco_yield.web import router as yield_web_router
from radar_service.auth_client import (
    COOKIE_NAME,
    DEMO_COOKIE_NAME,
    IntrospectFn,
    IntrospectionUnavailableError,
    introspect_with_model_host,
)
from radar_service.bridge_contract import (
    BRIDGE_CONTRACT_V1,
    BridgeUnavailableError,
    fetch_model_public_keys,
)
from radar_service.routers.crypto_public_router import router as crypto_public_router
from radar_service.routers.r_live_public_router import router as r_live_public_router
from radar_service.routers.rwa_basis_public_router import router as rwa_basis_public_router

TEMPLATES_ROOT = Path(__file__).resolve().parent / "templates"


def _is_offline_fixture_mode() -> bool:
    return os.getenv("FINCO_RADAR_OFFLINE_FIXTURE", "0").strip().lower() in ("1", "true", "yes", "on")


def _offline_fixture_snapshot() -> TerminalSnapshot:
    """Explicit offline test fixture snapshot (used ONLY when FINCO_RADAR_OFFLINE_FIXTURE=1)."""
    v = DisplayValue("0", "0.00")
    snap = TerminalSnapshot(
        TerminalStatus.TERMINAL_OK,
        datetime(2026, 11, 22, 0, 0, 0, tzinfo=timezone.utc),
        AssetHeader("OFFLINE_FIXTURE", "Offline Test Fixture Asset", "offline-fixture", 1, "0x0", "1:0x0", "fixture"),
        ReferencePanel(
            v, v, v, v, v, "2026-11-22T00:00:00+00:00", v,
            "FIXTURE", "NOT_HALTED", "CURRENT", "UNRESOLVED", "NONE", "CURRENT",
            True, (), "Explicit offline fixture mode (FINCO_RADAR_OFFLINE_FIXTURE=1)",
        ),
        (), (),
        LiquidityPanel(
            v, v, v, "WITHIN_POLICY", "WITHIN_POLICY", v, v,
            False, False, "fixture", "fixture", "fixture", "fixture",
            "COST_INCLUSION_UNRESOLVED", "Provider cost inclusion is unresolved.",
        ),
        SignalPanel(False, "SIGNALS SUPPRESSED", ("OFFLINE_FIXTURE_MODE",), (), "NO MATERIAL SIGNAL"),
        HistoryPanel(False, "No previous comparable observation available", (), "fixture"),
        (CandidateAuditEntry("OFFLINE_FIXTURE", "SELECTED"),),
        "fixture", "", "offline-fixture",
    )
    return replace(snap, terminal_snapshot_digest=reconstruct_terminal_digest(snap))


def _unconfigured_live_snapshot() -> TerminalSnapshot:
    """Honest degraded snapshot when no live persisted snapshot store is populated yet.

    NEVER masquerades as TERMINAL_OK production data.
    """
    v = DisplayValue("0", "0.00")
    now = datetime.now(timezone.utc)
    snap = TerminalSnapshot(
        TerminalStatus.TERMINAL_INPUT_INVALID,
        now,
        AssetHeader("UNCONFIGURED", "No Persisted Snapshot Loaded", "unconfigured", 1, "0x0", "1:0x0", "unconfigured"),
        ReferencePanel(
            v, v, v, v, v, now.isoformat(), v,
            "UNAVAILABLE", "NOT_HALTED", "STALE", "UNRESOLVED", "NONE", "STALE",
            False, ("NO_PERSISTED_SNAPSHOT",), "No persisted collector snapshot available; run r_live_collect.",
        ),
        (), (),
        LiquidityPanel(
            v, v, v, "WITHIN_POLICY", "WITHIN_POLICY", v, v,
            False, False, "unavailable", "unavailable", "unavailable", "unavailable",
            "COST_INCLUSION_UNRESOLVED", "No live snapshot loaded.",
        ),
        SignalPanel(False, "SIGNALS SUPPRESSED", ("NO_PERSISTED_SNAPSHOT",), (), "NO MATERIAL SIGNAL"),
        HistoryPanel(False, "No previous comparable observation available", (), "unconfigured"),
        (CandidateAuditEntry("UNCONFIGURED", "NO_SNAPSHOT"),),
        "unconfigured", "", "live-store-empty",
    )
    return replace(snap, terminal_snapshot_digest=reconstruct_terminal_digest(snap))


def _default_runtime_snapshot() -> TerminalSnapshot:
    if _is_offline_fixture_mode():
        return _offline_fixture_snapshot()
    return _unconfigured_live_snapshot()


def create_radar_service_app(
    *,
    snapshot_provider: Optional[Callable[[], TerminalSnapshot]] = None,
    introspector: Optional[IntrospectFn] = None,
) -> FastAPI:
    provider = snapshot_provider or _default_runtime_snapshot
    auth_fn = introspector or introspect_with_model_host

    app = create_radar_app(provider)
    app.title = "FINCO Radar Standalone Service"
    app.version = "0.2.0"
    app.state.introspector = auth_fn

    # Mount full standalone Radar / R-LIVE / RWA-Basis / Crypto / Yield routers
    app.include_router(yield_web_router)
    app.include_router(r_live_public_router, prefix="/api/v1.1")
    app.include_router(rwa_basis_public_router, prefix="/api/v1.1")
    app.include_router(crypto_public_router)

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "service": "finco-radar",
            "version": app.version,
            "mode": "offline_fixture" if _is_offline_fixture_mode() else "live_store",
        }

    @app.get("/ready")
    def ready():
        import json as _json
        required_files = [
            TERMINAL_ROOT / "templates" / "radar_terminal.html",
            TERMINAL_ROOT / "static" / "radar_terminal.js",
            TERMINAL_ROOT / "static" / "radar_terminal.css",
            TEMPLATES_ROOT / "yield" / "explore.html",
            TEMPLATES_ROOT / "yield" / "base.html",
        ]
        missing = [p.name for p in required_files if not p.is_file()]
        if missing:
            raise HTTPException(status_code=503, detail=f"Missing packaged assets: {missing}")

        env_probe = build_evidence_envelope(surface="radar", evidence_type="readiness_probe", payload={"probe": "ready"})
        yield_count = len(load_bundled_registry().all())
        auth_configured = bool(
            os.getenv("FINCO_MODEL_INTERNAL_AUTH_URL", "").strip()
            and os.getenv("FINCO_INTERNAL_AUTH_INTROSPECT_TOKEN", "").strip()
        )
        snap_path_raw = os.getenv("FINCO_RLIVE_SNAPSHOT_PATH", "").strip()
        if _is_offline_fixture_mode():
            snapshot_mode = "OFFLINE_FIXTURE"
        elif snap_path_raw and Path(snap_path_raw).is_file():
            try:
                parsed = _json.loads(Path(snap_path_raw).read_text(encoding="utf-8"))
                if not isinstance(parsed, dict):
                    raise ValueError("snapshot root must be JSON object")
                snapshot_mode = "LIVE_STORE_AVAILABLE"
            except Exception as exc:
                raise HTTPException(status_code=503, detail=f"LIVE_STORE_CORRUPT: {exc}") from exc
        else:
            snapshot_mode = "LIVE_STORE_UNPOPULATED"
        return {
            "status": "ready",
            "service": "finco-radar",
            "envelope_schema": env_probe.schema,
            "yield_registry_count": yield_count,
            "auth_authority_configured": auth_configured,
            "snapshot_mode": snapshot_mode,
        }

    @app.get("/api/v1/radar/assets")
    def list_radar_assets():
        from finco_radar.authority.r_live_policy import APPROVED_RLIVE_ASSETS
        items = [
            {
                "economic_asset_uid": p.economic_asset_uid,
                "canonical_id": p.asset_key.canonical_id,
                "symbol": p.symbol,
                "authority_version": p.authority_version,
            }
            for p in APPROVED_RLIVE_ASSETS.values()
        ]
        return JSONResponse({"schema": "finco.radar.assets.v1", "count": len(items), "items": items})

    @app.get("/api/v1/radar/assets/{economic_asset_uid}")
    def get_radar_asset(economic_asset_uid: str):
        from finco_radar.authority.r_live_policy import APPROVED_RLIVE_ASSETS
        for p in APPROVED_RLIVE_ASSETS.values():
            if p.economic_asset_uid == economic_asset_uid or p.symbol.lower() == economic_asset_uid.lower():
                return JSONResponse({
                    "schema": "finco.radar.asset.detail.v1",
                    "economic_asset_uid": p.economic_asset_uid,
                    "canonical_id": p.asset_key.canonical_id,
                    "symbol": p.symbol,
                    "authority_version": p.authority_version,
                })
        raise HTTPException(status_code=404, detail="Unknown Radar economic asset")

    @app.get("/api/v1/radar/session-context")
    def session_context(
        finco_session: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
        finco_demo: Optional[str] = Cookie(default=None, alias=DEMO_COOKIE_NAME),
    ):
        if not finco_session and not finco_demo:
            raise HTTPException(status_code=401, detail="Authentication required")
        try:
            verdict = auth_fn(finco_session, finco_demo)
        except IntrospectionUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        if not verdict.authenticated:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        return JSONResponse({
            "authenticated": True,
            "session_kind": verdict.session_kind,
            "user_id": verdict.user_id,
            "tenant_id": verdict.tenant_id,
            "entitlements": list(verdict.entitlements),
            "wallet_verified": verdict.wallet_verified,
            "wallet_address": verdict.wallet_address,
        })

    @app.get("/api/v1.1/radar/bridge-contract")
    def bridge_contract():
        return JSONResponse(BRIDGE_CONTRACT_V1)

    @app.get("/api/v1.1/radar/bridge/model-keys")
    def bridge_model_keys():
        try:
            keys = fetch_model_public_keys()
        except BridgeUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return JSONResponse({
            "schema": "finco.radar.bridge.model_keys.v1",
            "mode": "READ_ONLY",
            "keys": keys,
        })

    return app


app = create_radar_service_app()
