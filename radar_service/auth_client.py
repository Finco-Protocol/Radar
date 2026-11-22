"""Fail-closed service-to-service auth introspection client for FincoRadar.

Calls POST /internal/v1/auth/introspect on the authoritative FincoProtocol Model host.
Never shares FINCO_SECRET_KEY or reads Model databases directly.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any, Callable, Optional

import httpx


SCHEMA_VERSION = "finco.internal.auth.introspect.v1"
DEFAULT_AUDIENCE = "finco-radar-v1"
DEFAULT_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class IntrospectedIdentity:
    authenticated: bool
    session_kind: str
    user_id: Optional[str]
    tenant_id: Optional[str]
    entitlements: tuple[str, ...]
    error: Optional[str] = None


def introspect_with_model_host(
    *,
    session_token: Optional[str] = None,
    demo_session_token: Optional[str] = None,
    base_url: Optional[str] = None,
    internal_token: Optional[str] = None,
    audience: str = DEFAULT_AUDIENCE,
    timeout_s: float = DEFAULT_TIMEOUT_SECONDS,
    transport: Optional[httpx.BaseTransport] = None,
) -> IntrospectedIdentity:
    """Verify opaque session cookies against FincoProtocol Model host; always fails closed."""
    url_root = (base_url if base_url is not None else os.environ.get("FINCO_MODEL_INTERNAL_AUTH_URL", "")).strip().rstrip("/")
    token = (internal_token if internal_token is not None else os.environ.get("FINCO_INTERNAL_AUTH_INTROSPECT_TOKEN", "")).strip()
    if not url_root or not token:
        return IntrospectedIdentity(False, "anonymous", None, None, (), error="INTROSPECT_NOT_CONFIGURED")
    if not session_token and not demo_session_token:
        return IntrospectedIdentity(False, "anonymous", None, None, (), error=None)

    try:
        with httpx.Client(base_url=url_root, timeout=timeout_s, transport=transport) as client:
            resp = client.post(
                "/internal/v1/auth/introspect",
                headers={"X-Finco-Internal-Token": token},
                json={
                    "audience": audience,
                    "session_token": session_token,
                    "demo_session_token": demo_session_token,
                },
            )
    except httpx.HTTPError as exc:
        return IntrospectedIdentity(False, "anonymous", None, None, (), error=f"INTROSPECT_TRANSPORT_ERROR:{type(exc).__name__}")

    if resp.status_code != 200:
        return IntrospectedIdentity(False, "anonymous", None, None, (), error=f"INTROSPECT_HTTP_{resp.status_code}")

    try:
        data: dict[str, Any] = resp.json()
    except ValueError:
        return IntrospectedIdentity(False, "anonymous", None, None, (), error="INTROSPECT_INVALID_JSON")

    if data.get("schema_version") != SCHEMA_VERSION or data.get("audience") != audience:
        return IntrospectedIdentity(False, "anonymous", None, None, (), error="INTROSPECT_CONTRACT_MISMATCH")

    if not bool(data.get("authenticated")):
        return IntrospectedIdentity(False, "anonymous", None, None, (), error=None)

    ents = data.get("entitlements")
    if not isinstance(ents, list) or not all(isinstance(x, str) for x in ents):
        return IntrospectedIdentity(False, "anonymous", None, None, (), error="INTROSPECT_INVALID_ENTITLEMENTS")

    return IntrospectedIdentity(
        authenticated=True,
        session_kind=str(data.get("session_kind") or "anonymous"),
        user_id=str(data["user_id"]) if data.get("user_id") is not None else None,
        tenant_id=str(data["tenant_id"]) if data.get("tenant_id") is not None else None,
        entitlements=tuple(ents),
        error=None,
    )


IntrospectFn = Callable[..., IntrospectedIdentity]
