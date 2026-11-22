"""Runnable standalone FINCO Radar FastAPI service host (Option B).

Mounts:
- GET /health, GET /ready (fail-closed asset & contract readiness check)
- Authentic finco_radar.terminal.web R6 terminal (/radar, /radar/api/snapshot, /radar/static/*)
- GET /api/v1/radar/session-context (authenticated via Model host internal introspection)
- GET /api/v1.1/radar/bridge-contract (read-only Model <-> Market Bridge v1 descriptor)
"""
from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import replace
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
from radar_service.auth_client import IntrospectFn, introspect_with_model_host
from radar_service.bridge_contract import BRIDGE_CONTRACT_V1


def _default_offline_snapshot() -> TerminalSnapshot:
    """Deterministic offline-safe initial snapshot (no live RPC/provider call on boot)."""
    v = DisplayValue("0", "0.00")
    snap = TerminalSnapshot(
        TerminalStatus.TERMINAL_OK,
        datetime(2026, 11, 22, 0, 0, 0, tzinfo=timezone.utc),
        AssetHeader("OFFLINE", "Offline Standby Asset", "offline-standby", 1, "0x0", "1:0x0", "standby"),
        ReferencePanel(
            v, v, v, v, v, "2026-11-22T00:00:00+00:00", v,
            "STANDBY", "NOT_HALTED", "CURRENT", "UNRESOLVED", "NONE", "CURRENT",
            True, (), "Offline deterministic standby snapshot",
        ),
        (), (),
        LiquidityPanel(
            v, v, v, "WITHIN_POLICY", "WITHIN_POLICY", v, v,
            False, False, "standby", "standby", "standby", "standby",
            "COST_INCLUSION_UNRESOLVED", "Provider cost inclusion is unresolved.",
        ),
        SignalPanel(False, "SIGNALS SUPPRESSED", ("OFFLINE_STANDBY",), (), "NO MATERIAL SIGNAL"),
        HistoryPanel(False, "No previous comparable observation available", (), "standby"),
        (CandidateAuditEntry("OFFLINE", "SELECTED"),),
        "standby", "", "standalone-boot",
    )
    return replace(snap, terminal_snapshot_digest=reconstruct_terminal_digest(snap))


def create_radar_service_app(
    *,
    snapshot_provider: Optional[Callable[[], TerminalSnapshot]] = None,
    introspector: Optional[IntrospectFn] = None,
) -> FastAPI:
    provider = snapshot_provider or _default_offline_snapshot
    auth_fn = introspector or introspect_with_model_host

    app = create_radar_app(provider)
    app.title = "FINCO Radar Standalone Service"
    app.version = "0.1.0"

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "finco-radar", "version": "0.1.0"}

    @app.get("/ready")
    def ready():
        required_assets = (
            TERMINAL_ROOT / "templates" / "radar_terminal.html",
            TERMINAL_ROOT / "static" / "radar_terminal.css",
            TERMINAL_ROOT / "static" / "radar_terminal.js",
        )
        missing = [p.name for p in required_assets if not p.is_file()]
        if missing:
            return JSONResponse(status_code=503, content={"ready": False, "missing_assets": missing})
        probe_env = build_evidence_envelope(
            surface="finco_radar.service.ready",
            evidence_type="readiness-probe",
            payload={"service": "finco-radar"},
            authority_refs=("finco_radar",),
        )
        return {
            "ready": True,
            "service": "finco-radar",
            "envelope_schema": probe_env.schema,
        }

    @app.get("/api/v1/radar/session-context")
    def radar_session_context(
        finco_session: Optional[str] = Cookie(default=None),
        finco_demo_session: Optional[str] = Cookie(default=None),
    ):
        ident = auth_fn(session_token=finco_session, demo_session_token=finco_demo_session)
        if ident.error and ident.error.startswith(("INTROSPECT_TRANSPORT_ERROR", "INTROSPECT_HTTP_5")):
            raise HTTPException(status_code=503, detail="AUTH_INTROSPECTION_UNAVAILABLE")
        if not ident.authenticated:
            raise HTTPException(status_code=401, detail="AUTHENTICATION_REQUIRED")
        return {
            "authenticated": True,
            "session_kind": ident.session_kind,
            "user_id": ident.user_id,
            "tenant_id": ident.tenant_id,
            "entitlements": list(ident.entitlements),
        }

    @app.get("/api/v1.1/radar/bridge-contract")
    def bridge_contract():
        return BRIDGE_CONTRACT_V1

    return app


app = create_radar_service_app()
