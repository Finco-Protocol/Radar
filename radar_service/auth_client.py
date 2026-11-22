"""Fail-closed internal auth introspection client for standalone FINCO Radar.

Cookie contract matches FincoProtocol app/auth.py verbatim:
- COOKIE_NAME = "finco_session"
- DEMO_COOKIE_NAME = "finco_demo"

Security invariants:
- No shared FINCO_SECRET_KEY copy, no direct Model DB access, no client entitlement trust.
- Strict typed response parsing:
  - Must be a JSON object (rejects list/str/int/null safely without 500 or token leakage).
  - schema == "finco.internal.auth.introspect.v1", audience == "radar".
  - authenticated MUST be strict bool (isinstance(..., bool)) — rejects "true"/"false"/1/0/None.
  - When authenticated is True: requires session_kind in {"user", "demo"}, non-empty str
    user_id & tenant_id, list[str] entitlements.
- Any upstream error, timeout, missing config, or malformed payload raises
  IntrospectionUnavailableError (HTTP 503 fail-closed), NEVER mapped to ALLOW/INACTIVE.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any, Callable, Mapping, Optional

import httpx

COOKIE_NAME = "finco_session"
DEMO_COOKIE_NAME = "finco_demo"
INTROSPECT_SCHEMA = "finco.internal.auth.introspect.v1"
EXPECTED_AUDIENCE = "radar"
ALLOWED_SESSION_KINDS = frozenset({"user", "demo"})
ALLOWED_DECISIONS = frozenset({"PUBLIC", "ALLOW", "INACTIVE", "DENY"})


class IntrospectionUnavailableError(RuntimeError):
    """Raised when the Model auth authority is unconfigured, unreachable, or returns malformed data."""


@dataclass(frozen=True)
class IntrospectedSession:
    authenticated: bool
    session_kind: Optional[str] = None
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    entitlements: tuple[str, ...] = ()
    entitlement_decisions: Mapping[str, Mapping[str, Any]] | None = None
    wallet_verified: bool = False
    wallet_address: Optional[str] = None


IntrospectFn = Callable[[Optional[str], Optional[str]], IntrospectedSession]


def parse_introspect_payload(raw: Any) -> IntrospectedSession:
    """Strictly validate Model host introspect JSON payload. Fail closed on any violation."""
    if not isinstance(raw, dict):
        raise IntrospectionUnavailableError("Malformed auth authority payload: expected JSON object")

    schema = raw.get("schema")
    if schema != INTROSPECT_SCHEMA:
        raise IntrospectionUnavailableError("Unexpected auth authority schema version")

    audience = raw.get("audience")
    if audience != EXPECTED_AUDIENCE:
        raise IntrospectionUnavailableError("Auth authority audience mismatch")

    authenticated = raw.get("authenticated")
    if type(authenticated) is not bool:
        raise IntrospectionUnavailableError("Malformed auth authority payload: authenticated must be bool")

    decisions_raw = raw.get("entitlement_decisions")
    validated_decisions: dict[str, dict[str, Any]] = {}
    if decisions_raw is not None:
        if not isinstance(decisions_raw, dict):
            raise IntrospectionUnavailableError("Malformed entitlement_decisions: expected object")
        for res_key, dec_obj in decisions_raw.items():
            if not isinstance(res_key, str) or not isinstance(dec_obj, dict):
                raise IntrospectionUnavailableError("Malformed entitlement_decisions entry")
            dec_val = dec_obj.get("decision")
            if not isinstance(dec_val, str) or dec_val not in ALLOWED_DECISIONS:
                raise IntrospectionUnavailableError("Invalid entitlement decision value")
            validated_decisions[res_key] = {
                "decision": dec_val,
                "reason": str(dec_obj.get("reason", "")),
            }

    if not authenticated:
        return IntrospectedSession(
            authenticated=False,
            entitlement_decisions=validated_decisions or None,
        )

    session_kind = raw.get("session_kind")
    if not isinstance(session_kind, str) or session_kind not in ALLOWED_SESSION_KINDS:
        raise IntrospectionUnavailableError("Invalid or unsupported session_kind")

    user_id = raw.get("user_id")
    tenant_id = raw.get("tenant_id")
    if not isinstance(user_id, str) or not user_id.strip():
        raise IntrospectionUnavailableError("Authenticated session missing valid user_id")
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise IntrospectionUnavailableError("Authenticated session missing valid tenant_id")

    entitlements_raw = raw.get("entitlements")
    if not isinstance(entitlements_raw, list) or not all(isinstance(x, str) for x in entitlements_raw):
        raise IntrospectionUnavailableError("Malformed entitlements list")

    wallet_verified = raw.get("wallet_verified", False)
    if type(wallet_verified) is not bool:
        raise IntrospectionUnavailableError("Malformed wallet_verified flag")

    wallet_address = raw.get("wallet_address")
    if wallet_address is not None and not isinstance(wallet_address, str):
        raise IntrospectionUnavailableError("Malformed wallet_address")

    return IntrospectedSession(
        authenticated=True,
        session_kind=session_kind,
        user_id=user_id,
        tenant_id=tenant_id,
        entitlements=tuple(entitlements_raw),
        entitlement_decisions=validated_decisions or None,
        wallet_verified=wallet_verified,
        wallet_address=wallet_address,
    )


def introspect_with_model_host(
    session_cookie: Optional[str],
    demo_cookie: Optional[str] = None,
    *,
    base_url: Optional[str] = None,
    internal_token: Optional[str] = None,
    timeout_seconds: float = 3.0,
) -> IntrospectedSession:
    """Call Model host POST /internal/v1/auth/introspect. Always fails closed."""
    resolved_url = (base_url or os.getenv("FINCO_MODEL_INTERNAL_AUTH_URL", "")).strip().rstrip("/")
    resolved_token = (internal_token or os.getenv("FINCO_INTERNAL_AUTH_INTROSPECT_TOKEN", "")).strip()
    if not resolved_url or not resolved_token:
        raise IntrospectionUnavailableError("Model internal auth authority is not configured")

    if not session_cookie and not demo_cookie:
        return IntrospectedSession(authenticated=False)

    payload: dict[str, Any] = {
        "audience": EXPECTED_AUDIENCE,
        "session_cookie": session_cookie,
        "demo_cookie": demo_cookie,
    }
    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            resp = client.post(
                f"{resolved_url}/internal/v1/auth/introspect",
                json=payload,
                headers={"X-Finco-Internal-Token": resolved_token},
            )
    except httpx.HTTPError as exc:
        raise IntrospectionUnavailableError("Model auth authority unreachable") from exc

    if resp.status_code != 200:
        raise IntrospectionUnavailableError(f"Model auth authority rejected request (HTTP {resp.status_code})")

    try:
        raw = resp.json()
    except ValueError as exc:
        raise IntrospectionUnavailableError("Model auth authority returned non-JSON body") from exc

    return parse_introspect_payload(raw)
