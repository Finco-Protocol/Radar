"""Comprehensive M2-B/M3/B2/B3/B4 standalone Radar service, auth, entitlement, Yield, gateway, and collector tests."""
from __future__ import annotations

import asyncio
import importlib
import os
from pathlib import Path
import re

from fastapi.testclient import TestClient
import pytest

from radar_service.app import create_radar_service_app
from radar_service.auth_client import (
    COOKIE_NAME,
    DEMO_COOKIE_NAME,
    IntrospectedSession,
    IntrospectionUnavailableError,
    parse_introspect_payload,
)
from radar_service.entitlements import (
    Decision,
    WalletContext,
    evaluate_resource_access,
    generate_csrf_token,
    validate_csrf_token,
)
from finco_yield.access import YieldAccessState, YieldResource, resolve_yield_access


def test_cookie_contract_matches_fincoprotocol_auth_py() -> None:
    assert COOKIE_NAME == "finco_session"
    assert DEMO_COOKIE_NAME == "finco_demo"


def test_strict_typed_introspect_parser_rejects_malformed_and_string_truthiness() -> None:
    # Reject non-object JSON
    for bad in ([], "ok", 123, None, True):
        with pytest.raises(IntrospectionUnavailableError):
            parse_introspect_payload(bad)

    # Reject string truthiness ("true", "false") and int 1/0
    for bad_auth in ("true", "false", 1, 0, None):
        with pytest.raises(IntrospectionUnavailableError):
            parse_introspect_payload({
                "schema": "finco.internal.auth.introspect.v1",
                "audience": "radar",
                "authenticated": bad_auth,
                "session_kind": "user",
                "user_id": "u1",
                "tenant_id": "t1",
                "entitlements": [],
            })

    # Reject wrong schema / audience
    with pytest.raises(IntrospectionUnavailableError):
        parse_introspect_payload({"schema": "wrong.v1", "audience": "radar", "authenticated": False})
    with pytest.raises(IntrospectionUnavailableError):
        parse_introspect_payload({"schema": "finco.internal.auth.introspect.v1", "audience": "model", "authenticated": False})

    # Reject missing user_id / tenant_id / invalid session_kind when authenticated=True
    with pytest.raises(IntrospectionUnavailableError):
        parse_introspect_payload({
            "schema": "finco.internal.auth.introspect.v1",
            "audience": "radar",
            "authenticated": True,
            "session_kind": "admin_override",
            "user_id": "u1",
            "tenant_id": "t1",
            "entitlements": [],
        })
    with pytest.raises(IntrospectionUnavailableError):
        parse_introspect_payload({
            "schema": "finco.internal.auth.introspect.v1",
            "audience": "radar",
            "authenticated": True,
            "session_kind": "user",
            "user_id": "",
            "tenant_id": "t1",
            "entitlements": [],
        })

    # Valid authenticated payload parses cleanly
    ok = parse_introspect_payload({
        "schema": "finco.internal.auth.introspect.v1",
        "audience": "radar",
        "authenticated": True,
        "session_kind": "demo",
        "user_id": "demo-1",
        "tenant_id": "demo-1",
        "entitlements": ["radar:read:public"],
        "wallet_verified": False,
        "wallet_address": None,
    })
    assert ok.authenticated is True
    assert ok.session_kind == "demo"
    assert ok.user_id == "demo-1"


def test_default_mode_does_not_masquerade_offline_fixture_as_terminal_ok(monkeypatch) -> None:
    monkeypatch.delenv("FINCO_RADAR_OFFLINE_FIXTURE", raising=False)
    app = create_radar_service_app()
    client = TestClient(app)

    r_ready = client.get("/ready")
    assert r_ready.status_code == 200
    assert r_ready.json()["snapshot_mode"] == "LIVE_STORE_UNPOPULATED"

    r_snap = client.get("/radar/api/snapshot")
    assert r_snap.status_code == 200
    body = r_snap.json()
    assert body["status"] == "TERMINAL_INPUT_INVALID"

    # Explicit offline fixture mode is clearly labeled
    monkeypatch.setenv("FINCO_RADAR_OFFLINE_FIXTURE", "1")
    app_fix = create_radar_service_app()
    client_fix = TestClient(app_fix)
    assert client_fix.get("/ready").json()["snapshot_mode"] == "OFFLINE_FIXTURE"
    assert client_fix.get("/radar/api/snapshot").json()["status"] == "TERMINAL_OK"


def test_full_product_routes_mounted_and_functional(monkeypatch) -> None:
    monkeypatch.setenv("FINCO_RADAR_OFFLINE_FIXTURE", "1")
    monkeypatch.setenv("FINCO_YIELD_ENABLED", "1")
    app = create_radar_service_app()
    client = TestClient(app)

    # Core Radar & Bridge
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
    assert client.get("/radar").status_code == 200
    assert client.get("/radar/api/snapshot").status_code == 200
    assert client.get("/api/v1.1/radar/bridge-contract").json()["mode"] == "READ_ONLY"

    # Yield Web & API (real packaged Jinja2 templates + bundled registry!)
    r_yield = client.get("/yield")
    assert r_yield.status_code == 200
    assert "text/html" in r_yield.headers.get("content-type", "")
    assert client.get("/yield/access.json").status_code == 200
    assert client.get("/yield/compare").status_code == 400  # requires >=2 uids
    r_cy_pre = client.get("/api/v1/crypto/yield")
    uids = [item["opportunity_uid"] for item in r_cy_pre.json()["items"][:2]]
    assert client.get(f"/yield/compare?uid={uids[0]}&uid={uids[1]}").status_code == 200

    # Crypto Tokenized & Yield APIs
    r_tok = client.get("/api/v1/crypto/tokenized")
    assert r_tok.status_code == 200
    assert r_tok.json()["count"] >= 1
    r_cy = client.get("/api/v1/crypto/yield")
    assert r_cy.status_code == 200
    assert r_cy.json()["count"] >= 1

    # R-LIVE & RWA-Basis Public APIs
    assert client.get("/api/v1.1/radar/r-live/assets").status_code == 200
    assert client.get("/api/v1.1/radar/rwa-basis").status_code == 200


def test_session_context_and_yield_entitlement_fail_closed_matrix(monkeypatch) -> None:
    def _stub_introspect(session_cookie, demo_cookie):
        if session_cookie == "valid-user":
            return IntrospectedSession(
                authenticated=True,
                session_kind="user",
                user_id="u-1",
                tenant_id="t-1",
                entitlements=("yield.history",),
                wallet_verified=True,
                wallet_address="0x1234",
            )
        if demo_cookie == "valid-demo":
            return IntrospectedSession(
                authenticated=True,
                session_kind="demo",
                user_id="demo-1",
                tenant_id="demo-1",
                entitlements=("radar:read:public",),
            )
        if session_cookie == "boom":
            raise IntrospectionUnavailableError("upstream down")
        return IntrospectedSession(authenticated=False)

    app = create_radar_service_app(introspector=_stub_introspect)
    client = TestClient(app)

    # Unauthenticated -> 401
    assert client.get("/api/v1/radar/session-context").status_code == 401

    # Valid finco_demo cookie -> 200
    client.cookies.set(DEMO_COOKIE_NAME, "valid-demo")
    r_demo = client.get("/api/v1/radar/session-context")
    assert r_demo.status_code == 200
    assert r_demo.json()["session_kind"] == "demo"
    client.cookies.clear()

    # Valid finco_session cookie -> 200
    client.cookies.set(COOKIE_NAME, "valid-user")
    r_user = client.get("/api/v1/radar/session-context")
    assert r_user.status_code == 200
    assert r_user.json()["user_id"] == "u-1"
    client.cookies.clear()

    # Upstream error -> 503 fail-closed
    client.cookies.set(COOKIE_NAME, "boom")
    assert client.get("/api/v1/radar/session-context").status_code == 503
    client.cookies.clear()

    # Entitlement state machine: authority_error NEVER maps to INACTIVE or ALLOW
    monkeypatch.setenv("FINCO_TOKEN_GATING_ACTIVE", "0")
    dec_err = asyncio.run(evaluate_resource_access("yield.history", WalletContext(authority_error=True)))
    assert dec_err.decision is Decision.DENY
    assert dec_err.reason_code == "ENTITLEMENT_AUTHORITY_UNAVAILABLE"

    # PUBLIC always ALLOW with PUBLIC_RESOURCE
    dec_pub = asyncio.run(evaluate_resource_access("yield.basic", WalletContext()))
    assert dec_pub.decision is Decision.ALLOW and dec_pub.reason_code == "PUBLIC_RESOURCE"

    # CSRF validation
    tok = generate_csrf_token("u-1")
    assert validate_csrf_token("u-1", tok) is True
    assert validate_csrf_token("u-2", tok) is False
    assert validate_csrf_token("u-1", "tampered.mac") is False


def test_nginx_gateway_parity_and_systemd_collector_units() -> None:
    root = Path(__file__).resolve().parents[1]
    nginx_conf = (root / "deploy" / "nginx" / "radar_gateway_candidate.conf").read_text(encoding="utf-8")

    # /internal/ must be blocked with 403
    assert "location ^~ /internal/" in nginx_conf and "return 403;" in nginx_conf

    # Every Radar upstream location must match a real mounted OpenAPI path prefix!
    app = create_radar_service_app()
    openapi_paths = set(app.openapi()["paths"].keys())
    radar_locs = re.findall(r"location\s+(?:=|\^~)\s+(\S+)\s*\{\s*proxy_pass\s+http://finco_radar_upstream;", nginx_conf)
    assert len(radar_locs) >= 8
    for loc in radar_locs:
        matched = any(p == loc or p.startswith(loc) or p.startswith(loc.rstrip("/") + "/") for p in openapi_paths)
        assert matched, f"Nginx proxies {loc} to Radar but no matching route exists in radar_service.app!"

    # All 4 collector families import cleanly and systemd units have zero legacy monorepo paths
    for mod_name in (
        "radar_service.rwa.r_live_collect",
        "radar_service.rwa.tokenized_collect",
        "finco_yield.collect_live",
        "finco_yield.evaluate_alerts",
    ):
        mod = importlib.import_module(mod_name)
        assert "site-packages" in Path(mod.__file__).resolve().parts

    for svc in sorted((root / "deploy").rglob("*.service")):
        txt = svc.read_text(encoding="utf-8")
        assert "/opt/finco_protocol" not in txt, f"Legacy venv path in {svc}"
        assert "app.radar_rwa" not in txt, f"Legacy module path in {svc}"
