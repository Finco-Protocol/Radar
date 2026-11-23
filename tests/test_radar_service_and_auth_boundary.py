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

    # Explicit offline fixture mode is clearly labeled in dev/test
    monkeypatch.setenv("FINCO_RADAR_OFFLINE_FIXTURE", "1")
    monkeypatch.delenv("FINCO_ENV", raising=False)
    app_fix = create_radar_service_app()
    client_fix = TestClient(app_fix)
    assert client_fix.get("/health").json()["mode"] == "offline_fixture"
    assert client_fix.get("/ready").json()["snapshot_mode"] == "OFFLINE_FIXTURE"
    assert client_fix.get("/radar/api/snapshot").json()["status"] == "TERMINAL_OK"

    # Offline fixture mode MUST be disabled in staging and production
    for env_name in ("staging", "production", "prod"):
        monkeypatch.setenv("FINCO_ENV", env_name)
        assert client_fix.get("/health").json()["mode"] == "live_store"
        assert client_fix.get("/ready").json()["snapshot_mode"] == "LIVE_STORE_UNPOPULATED"
        assert client_fix.get("/radar/api/snapshot").json()["status"] == "TERMINAL_INPUT_INVALID"
    monkeypatch.delenv("FINCO_ENV", raising=False)


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
        assert "/opt/finco_protocol" not in txt, f"Legacy /opt/finco_protocol path in {svc}"
        assert "/opt/finco_staging" not in txt, f"Legacy /opt/finco_staging path in {svc}"
        assert "app.radar_rwa" not in txt, f"Legacy module path in {svc}"


def test_correction_a_security_oracle_and_collector_execution(monkeypatch, tmp_path) -> None:
    import shutil
    import subprocess
    import radar_service

    # 1. Both restored stock_token_oracle JSON files are packaged inside site-packages
    data_dir = Path(radar_service.__file__).resolve().parent / "rwa" / "data"
    assert (data_dir / "stock_token_oracle_feeds.json").is_file()
    assert (data_dir / "stock_token_oracle_candidates.json").is_file()

    # 2. Fail-closed when Model authority is configured but omits per-resource decision (NO local INACTIVE bypass)
    monkeypatch.setenv("FINCO_MODEL_INTERNAL_AUTH_URL", "http://127.0.0.1:19999")
    monkeypatch.setenv("FINCO_TOKEN_GATING_ACTIVE", "0")
    dec_missing = asyncio.run(evaluate_resource_access("crypto.api", WalletContext(subject_id="u1")))
    assert dec_missing.decision is Decision.DENY
    assert dec_missing.reason_code == "ENTITLEMENT_AUTHORITY_UNAVAILABLE"
    assert dec_missing.authority_available is False

    # Unknown resource always DENY
    dec_unk = asyncio.run(evaluate_resource_access("invented.resource", WalletContext(subject_id="u1")))
    assert dec_unk.decision is Decision.DENY and dec_unk.reason_code == "UNKNOWN_RESOURCE"

    # 3. Production CSRF secret must be explicitly configured (no silent ephemeral drift)
    monkeypatch.setenv("FINCO_ENV", "production")
    monkeypatch.delenv("FINCO_RADAR_CSRF_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        generate_csrf_token("u-prod")
    monkeypatch.setenv("FINCO_RADAR_CSRF_SECRET", "prod-csrf-secret-at-least-32-chars")
    prod_tok = generate_csrf_token("u-prod")
    assert validate_csrf_token("u-prod", prod_tok) is True
    monkeypatch.delenv("FINCO_ENV", raising=False)

    # 4. /crypto/alerts/* real SQLite persistence + cross-tenant isolation + canonical Model resource keys
    alerts_db = tmp_path / "alerts.db"
    monkeypatch.setenv("FINCO_RADAR_ALERTS_DB_PATH", str(alerts_db))
    import sqlite3
    with sqlite3.connect(str(alerts_db)) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS radar_crypto_alerts "
            "(alert_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info', is_read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)"
        )
        conn.execute("INSERT INTO radar_crypto_alerts VALUES ('a-1', 'u-crypto', 'Basis widened', 'warn', 0, '2026-11-22T00:00:00Z')")
        conn.execute("INSERT INTO radar_crypto_alerts VALUES ('a-other', 'u-other', 'Other tenant alert', 'info', 0, '2026-11-22T00:00:00Z')")
        conn.commit()

    def _stub(session_cookie, demo_cookie):
        if session_cookie == "ok-user":
            return IntrospectedSession(
                authenticated=True,
                session_kind="user",
                user_id="u-crypto",
                tenant_id="u-crypto",
                entitlements=("crypto.api",),
                entitlement_decisions={
                    "crypto.api": {"decision": "ALLOW", "reason": "HOLDER_ENTITLED"},
                    "tokenized.basic": {"decision": "ALLOW", "reason": "PUBLIC_RESOURCE"},
                    "tokenized.dislocation": {"decision": "ALLOW", "reason": "HOLDER_ENTITLED"},
                    "tokenized.history": {"decision": "ALLOW", "reason": "HOLDER_ENTITLED"},
                },
            )
        return IntrospectedSession(authenticated=False)

    app = create_radar_service_app(introspector=_stub)
    client = TestClient(app)
    assert client.post("/crypto/alerts/refresh").status_code == 401
    client.cookies.set(COOKIE_NAME, "ok-user")
    assert client.post("/crypto/alerts/refresh").status_code == 403  # missing CSRF
    valid_csrf = generate_csrf_token("u-crypto")
    assert client.post("/crypto/alerts/refresh", headers={"X-CSRF-Token": valid_csrf}).status_code == 200
    r_al = client.get("/crypto/alerts.json")
    assert r_al.status_code == 200 and r_al.json()["unread_count"] == 1
    # Cross-tenant read attempt -> 404
    assert client.post("/crypto/alerts/a-other/read", headers={"X-CSRF-Token": valid_csrf}).status_code == 404
    # Real persisted update -> unread_count drops to 0
    assert client.post("/crypto/alerts/a-1/read", headers={"X-CSRF-Token": valid_csrf}).status_code == 200
    assert client.get("/crypto/alerts.json").json()["unread_count"] == 0

    # Canonical Crypto API + Radar Assets
    r_tok = client.get("/api/v1/crypto/tokenized")
    assert r_tok.status_code == 200
    first_sym = r_tok.json()["items"][0]["underlying_symbol"]
    assert client.get(f"/api/v1/crypto/tokenized/{first_sym}/signals").status_code == 200
    assert client.get(f"/api/v1/crypto/tokenized/{first_sym}/integrity").status_code == 200
    assert client.get(f"/api/v1/crypto/tokenized/{first_sym}/history").status_code == 200
    assert client.get(f"/api/v1/crypto/tokenized/{first_sym}/dislocations").status_code == 200
    r_assets = client.get("/api/v1/radar/assets")
    assert r_assets.status_code == 200 and r_assets.json()["count"] >= 1

    # Real populated VenueMarketStore -> nonempty tokenized detail, basis_bps dislocations, history, signals, and corrupt 503
    from datetime import datetime, timezone
    from decimal import Decimal
    from finco_radar.venues.observations import FreshnessState, MarketObservation, ObservationStatus
    from finco_radar.venues.store import VenueMarketStore

    venue_db = tmp_path / "venues.db"
    vstore = VenueMarketStore(venue_db)
    now_iso = datetime.now(timezone.utc).isoformat()
    vstore.append_observation(MarketObservation(
        ts=now_iso,
        collected_at=now_iso,
        canonical_asset_id=first_sym,
        venue_id="robinhood_reference",
        instrument_id=f"{first_sym}-REF",
        instrument_type="equity_reference",
        price="200.00",
        reference_price="200.00",
        source="fixture_reference",
        freshness_state=FreshnessState.AVAILABLE,
        observation_status=ObservationStatus.OK,
        payload={"symbol": first_sym},
    ))
    vstore.append_observation(MarketObservation(
        ts=now_iso,
        collected_at=now_iso,
        canonical_asset_id=first_sym,
        venue_id="xstocks_solana",
        instrument_id=f"{first_sym}x",
        instrument_type="tokenized_stock",
        price="201.00",
        reference_price="200.00",
        basis_bps="50.00",
        source="fixture_venue",
        freshness_state=FreshnessState.AVAILABLE,
        observation_status=ObservationStatus.OK,
        payload={"symbol": first_sym},
    ))
    monkeypatch.setenv("FINCO_VENUE_DB_PATH", str(venue_db))

    r_tok_pop = client.get("/api/v1/crypto/tokenized")
    assert r_tok_pop.status_code == 200
    assert r_tok_pop.json()["history_available"] is True
    assert r_tok_pop.json()["observation_count"] == 2
    assert r_tok_pop.json()["data_origin"] == "VENUE_STORE"

    r_disloc = client.get(f"/api/v1/crypto/tokenized/{first_sym}/dislocations")
    assert r_disloc.status_code == 200
    assert r_disloc.json()["state"] == "AVAILABLE"
    assert r_disloc.json()["dislocations"][0]["basis_bps"] == "50.00"

    r_hist = client.get(f"/api/v1/crypto/tokenized/{first_sym}/history")
    assert r_hist.status_code == 200 and r_hist.json()["history_available"] is True
    assert len(r_hist.json()["points"]) >= 1

    r_sig = client.get(f"/api/v1/crypto/tokenized/{first_sym}/signals")
    assert r_sig.status_code == 200 and r_sig.json()["signals_active"] is True

    # Corrupt venue DB -> 503 fail-closed (never silent empty list)
    corrupt_vdb = tmp_path / "corrupt_venues.db"
    corrupt_vdb.write_bytes(b"not a valid sqlite database file")
    monkeypatch.setenv("FINCO_VENUE_DB_PATH", str(corrupt_vdb))
    assert client.get("/api/v1/crypto/tokenized").status_code == 503
    monkeypatch.delenv("FINCO_VENUE_DB_PATH", raising=False)

    # Real canonical SQLite RLiveSnapshotStore -> LIVE_STORE_AVAILABLE vs corrupt -> 503
    from radar_service.rwa.r_live_snapshot_store import RLiveSnapshotStore
    rlive_db = tmp_path / "r_live_snapshots.db"
    with RLiveSnapshotStore(path=str(rlive_db)) as rstore:
        written = rstore.write_batch([
            ("eip155:4663:0x0000000000000000000000000000000000000001", "AVAILABLE", {"symbol": "AAPL", "price_usd": "200.00"}),
        ])
        assert written == 1
    monkeypatch.delenv("FINCO_RADAR_OFFLINE_FIXTURE", raising=False)
    monkeypatch.setenv("R_LIVE_SNAPSHOT_DB_PATH", str(rlive_db))
    r_ready_live = client.get("/ready")
    assert r_ready_live.status_code == 200
    assert r_ready_live.json()["snapshot_mode"] == "LIVE_STORE_AVAILABLE"
    assert r_ready_live.json()["persisted_snapshot_count"] == 1

    corrupt_rlive = tmp_path / "corrupt_rlive.db"
    corrupt_rlive.write_bytes(b"corrupt sqlite header")
    monkeypatch.setenv("R_LIVE_SNAPSHOT_DB_PATH", str(corrupt_rlive))
    assert client.get("/ready").status_code == 503
    monkeypatch.delenv("R_LIVE_SNAPSHOT_DB_PATH", raising=False)

    # Verify unified /opt/finco_radar layout in finco-radar.service (no /opt/finco-radar mismatch)
    main_svc = (Path(__file__).resolve().parents[1] / "deploy" / "systemd" / "finco-radar.service").read_text(encoding="utf-8")
    assert "/opt/finco_radar" in main_svc and "/opt/finco-radar" not in main_svc

    # 5. Real flock -n -E 75 lock contention verification (prevents dual collector writers)
    flock_bin = shutil.which("flock")
    if flock_bin:
        lock_file = tmp_path / "collector.lock"
        holder = subprocess.Popen([flock_bin, str(lock_file), "sleep", "5"])
        try:
            import time
            time.sleep(0.15)
            contender = subprocess.run([flock_bin, "-n", "-E", "75", str(lock_file), "true"])
            assert contender.returncode == 75
        finally:
            holder.terminate()
            holder.wait(timeout=5)


def test_authenticated_yield_routes_csrf_and_fail_closed_503(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("FINCO_YIELD_ENABLED", "1")
    monkeypatch.setenv("FINCO_DB_PATH", str(tmp_path / "yield_watchlist.db"))

    def _stub(session_cookie, demo_cookie):
        if session_cookie == "valid-yield-user":
            return IntrospectedSession(
                authenticated=True,
                session_kind="user",
                user_id="u-yield-1",
                tenant_id="u-yield-1",
                entitlements=("yield.history",),
                entitlement_decisions={
                    "yield.basic": {"decision": "PUBLIC", "reason": "PUBLIC_RESOURCE"},
                    "yield.history": {"decision": "ALLOW", "reason": "HOLDER_ENTITLED"},
                    "yield.alerts": {"decision": "INACTIVE", "reason": "TOKEN_ENTITLEMENT_FEATURE_INACTIVE"},
                    "yield.advanced_compare": {"decision": "INACTIVE", "reason": "TOKEN_ENTITLEMENT_FEATURE_INACTIVE"},
                    "yield.execution_preflight": {"decision": "INACTIVE", "reason": "TOKEN_ENTITLEMENT_FEATURE_INACTIVE"},
                    "crypto.api": {"decision": "INACTIVE", "reason": "TOKEN_ENTITLEMENT_FEATURE_INACTIVE"},
                    "tokenized.basic": {"decision": "PUBLIC", "reason": "PUBLIC_RESOURCE"},
                    "tokenized.dislocation": {"decision": "INACTIVE", "reason": "TOKEN_ENTITLEMENT_FEATURE_INACTIVE"},
                    "tokenized.history": {"decision": "INACTIVE", "reason": "TOKEN_ENTITLEMENT_FEATURE_INACTIVE"},
                },
                wallet_verified=True,
                wallet_address="0x000000000000000000000000000000000000dead",
            )
        if session_cookie == "authority-down":
            raise IntrospectionUnavailableError("model unreachable")
        return IntrospectedSession(authenticated=False)

    app = create_radar_service_app(introspector=_stub)
    client = TestClient(app)

    client.cookies.set(COOKIE_NAME, "valid-yield-user")
    assert client.get("/yield").status_code == 200
    r_acc = client.get("/yield/access.json")
    assert r_acc.status_code == 200
    assert r_acc.json()["resources"]["yield.history"]["decision"] == "ALLOW"
    assert client.get("/yield/monitor").status_code == 200

    # Watchlist mutation requires valid user-bound CSRF token
    r_list = client.get("/api/v1/crypto/yield")
    uid = r_list.json()["items"][0]["opportunity_uid"]
    assert client.post(f"/yield/watchlist/{uid}").status_code == 403
    tok = generate_csrf_token("u-yield-1")
    assert client.post(f"/yield/watchlist/{uid}", headers={"X-CSRF-Token": tok}).status_code == 201
    assert client.get("/yield/watchlist.json").status_code == 200

    # Authority outage fails closed with HTTP 503 on authenticated Yield routes
    client.cookies.set(COOKIE_NAME, "authority-down")
    assert client.get("/yield/access.json").status_code == 503
