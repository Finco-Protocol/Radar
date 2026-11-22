"""Standalone Radar service boot, fail-closed auth introspection, bridge contract,
and nginx gateway path-routing boundary tests."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
import httpx

from radar_service.app import create_radar_service_app
from radar_service.auth_client import IntrospectedIdentity, SCHEMA_VERSION, introspect_with_model_host
from radar_service.bridge_contract import BRIDGE_CONTRACT_V1


def test_standalone_service_health_ready_terminal_and_bridge() -> None:
    app = create_radar_service_app()
    client = TestClient(app)

    h = client.get("/health")
    assert h.status_code == 200 and h.json()["service"] == "finco-radar"

    r = client.get("/ready")
    assert r.status_code == 200
    assert r.json()["ready"] is True
    assert r.json()["envelope_schema"] == "finco.evidence-envelope.v1"

    assert client.get("/radar").status_code == 200
    snap = client.get("/radar/api/snapshot")
    assert snap.status_code == 200 and snap.json()["status"] == "TERMINAL_OK"
    assert client.get("/radar/static/radar_terminal.css").status_code == 200
    assert client.get("/radar/static/radar_terminal.js").status_code == 200

    b = client.get("/api/v1.1/radar/bridge-contract")
    assert b.status_code == 200
    assert b.json() == BRIDGE_CONTRACT_V1
    assert b.json()["mode"] == "READ_ONLY"
    assert b.json()["mutations_permitted"] is False
    assert b.json()["financial_math_owner"] == "FincoProtocol"


def test_auth_introspect_client_fail_closed_matrix() -> None:
    # 1. Unconfigured -> fail closed
    res = introspect_with_model_host(session_token="abc", base_url="", internal_token="")
    assert not res.authenticated and res.error == "INTROSPECT_NOT_CONFIGURED"

    # 2. Upstream 503 -> fail closed
    t503 = httpx.MockTransport(lambda req: httpx.Response(503, json={"detail": "down"}))
    res503 = introspect_with_model_host(
        session_token="abc", base_url="http://model.internal", internal_token="tok-1234567890123456", transport=t503
    )
    assert not res503.authenticated and res503.error == "INTROSPECT_HTTP_503"

    # 3. Wrong audience in response -> fail closed
    twrong = httpx.MockTransport(
        lambda req: httpx.Response(
            200,
            json={
                "schema_version": SCHEMA_VERSION,
                "authenticated": True,
                "audience": "wrong-aud",
                "session_kind": "admin",
                "user_id": "1",
                "tenant_id": "1",
                "entitlements": ["radar:read"],
            },
        )
    )
    res_aud = introspect_with_model_host(
        session_token="abc", base_url="http://model.internal", internal_token="tok-1234567890123456", transport=twrong
    )
    assert not res_aud.authenticated and res_aud.error == "INTROSPECT_CONTRACT_MISMATCH"

    # 4. Valid authenticated response -> succeeds with minimum claims
    tok = httpx.MockTransport(
        lambda req: httpx.Response(
            200,
            json={
                "schema_version": SCHEMA_VERSION,
                "authenticated": True,
                "audience": "finco-radar-v1",
                "session_kind": "admin",
                "user_id": "42",
                "tenant_id": "42",
                "entitlements": ["radar:read", "crypto:read"],
            },
        )
    )
    res_ok = introspect_with_model_host(
        session_token="opaque-cookie", base_url="http://model.internal", internal_token="tok-1234567890123456", transport=tok
    )
    assert res_ok.authenticated is True
    assert res_ok.user_id == "42" and res_ok.tenant_id == "42"
    assert res_ok.entitlements == ("radar:read", "crypto:read")


def test_session_context_route_enforces_introspector_verdict() -> None:
    # Unauthenticated -> 401
    app_anon = create_radar_service_app(
        introspector=lambda **kw: IntrospectedIdentity(False, "anonymous", None, None, (), None)
    )
    assert TestClient(app_anon).get("/api/v1/radar/session-context").status_code == 401

    # Introspector outage -> 503 fail closed
    app_down = create_radar_service_app(
        introspector=lambda **kw: IntrospectedIdentity(False, "anonymous", None, None, (), "INTROSPECT_HTTP_503")
    )
    assert TestClient(app_down).get("/api/v1/radar/session-context").status_code == 503

    # Authenticated -> 200 with minimum claims
    app_ok = create_radar_service_app(
        introspector=lambda **kw: IntrospectedIdentity(True, "admin", "42", "42", ("radar:read",), None)
    )
    resp = TestClient(app_ok).get("/api/v1/radar/session-context", cookies={"finco_session": "opaque"})
    assert resp.status_code == 200
    assert resp.json()["user_id"] == "42"
    assert "opaque" not in resp.text


def test_nginx_gateway_candidate_preserves_model_routes_and_blocks_internal() -> None:
    root = Path(__file__).resolve().parents[1]
    conf = (root / "deploy" / "nginx" / "radar_gateway_candidate.conf").read_text(encoding="utf-8")
    for radar_loc in ("location = /radar", "location ^~ /radar/", "location = /crypto", "location ^~ /crypto/",
                      "location ^~ /api/v1/radar/", "location ^~ /api/v1/crypto/",
                      "location ^~ /api/v1.1/radar/", "location ^~ /api/v1.1/rwa-basis/"):
        assert radar_loc in conf
    # Must NEVER hijack broad /api/v1/ or /api/v1.1/ from Model
    assert "location ^~ /api/v1/ {" not in conf
    assert "location ^~ /api/v1.1/ {" not in conf
    # Internal auth endpoint must be denied from public internet
    assert "location ^~ /internal/" in conf and "return 403;" in conf
    # Default fallback routes to Model
    assert "proxy_pass http://finco_model_backend;" in conf
