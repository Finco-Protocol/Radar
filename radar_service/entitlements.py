"""Canonical standalone entitlement, wallet-context, and CSRF adapter for FINCO Radar/Yield.

Correction A security hardening:
- Removes any invented 'holder:all' wildcard.
- Never derives INACTIVE or ALLOW from a missing/incomplete/unavailable Model authority response:
  when FINCO_MODEL_INTERNAL_AUTH_URL is configured and a protected resource lacks an authoritative
  server-side decision, fails closed with Decision.DENY / ENTITLEMENT_AUTHORITY_UNAVAILABLE.
- Preserves exact Decision enum (ALLOW, INACTIVE, DENY) and ResourceAccessDecision contract.
- Fails closed in production (FINCO_ENV=production) if FINCO_RADAR_CSRF_SECRET (<16 chars) is unset,
  preventing multi-worker ephemeral CSRF secret drift.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import os
import secrets
from typing import Any, Mapping, Optional

from fastapi import Request

from radar_service.auth_client import (
    COOKIE_NAME,
    DEMO_COOKIE_NAME,
    IntrospectedSession,
    IntrospectionUnavailableError,
    introspect_with_model_host,
)

# Exact canonical resource keys matching FincoProtocol app.protocol.entitlement_evaluator
PUBLIC_RESOURCES = frozenset({"yield.basic", "tokenized.basic"})
HOLDER_RESOURCES = frozenset({
    "crypto.api",
    "tokenized.dislocation",
    "tokenized.history",
    "yield.history",
    "yield.advanced_compare",
    "yield.alerts",
    "yield.execution_preflight",
})


class Decision(str, Enum):
    ALLOW = "ALLOW"
    INACTIVE = "INACTIVE"
    DENY = "DENY"


@dataclass(frozen=True)
class WalletContext:
    subject_id: Optional[str] = None
    verified: bool = False
    wallet_address: Optional[str] = None
    entitlements: tuple[str, ...] = ()
    entitlement_decisions: Mapping[str, Mapping[str, Any]] | None = None
    authority_error: bool = False


@dataclass(frozen=True)
class ResourceAccessDecision:
    resource: str
    decision: Decision
    reason_code: str
    wallet_address: Optional[str] = None
    authority_available: bool = True
    feature_active: bool = False
    token_configured: bool = False

    @property
    def reason(self) -> str:
        return self.reason_code


def _authority_configured() -> bool:
    return bool(os.getenv("FINCO_MODEL_INTERNAL_AUTH_URL", "").strip())


def _token_gating_active() -> bool:
    return os.getenv("FINCO_TOKEN_GATING_ACTIVE", "0").strip().lower() in ("1", "true", "yes", "on")


def _token_deployment_configured() -> bool:
    return bool(os.getenv("FINCO_TOKEN_CONTRACT_ADDRESS", "").strip())


_EPHEMERAL_CSRF_SECRET = secrets.token_bytes(32)


def _csrf_secret() -> bytes:
    raw = os.getenv("FINCO_RADAR_CSRF_SECRET", "").strip()
    if raw:
        if len(raw) < 16:
            raise RuntimeError("FINCO_RADAR_CSRF_SECRET must be at least 16 characters")
        return raw.encode("utf-8")
    if os.getenv("FINCO_ENV", "").strip().lower() in ("prod", "production", "staging"):
        raise RuntimeError("FINCO_RADAR_CSRF_SECRET must be explicitly configured in staging/production")
    return _EPHEMERAL_CSRF_SECRET


def generate_csrf_token(session_id: str = "") -> str:
    """Generate HMAC-SHA256 CSRF token bound to session_id (using Radar's own secret)."""
    sid = session_id or "anonymous"
    nonce = secrets.token_hex(16)
    mac = hmac.new(_csrf_secret(), f"{sid}:{nonce}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{nonce}.{mac}"


def validate_csrf_token(session_id: str, token: Optional[str]) -> bool:
    """Validate HMAC-SHA256 CSRF token using constant-time comparison."""
    if not token or not isinstance(token, str) or "." not in token:
        return False
    nonce, provided_mac = token.split(".", 1)
    if not nonce or not provided_mac:
        return False
    expected_mac = hmac.new(
        _csrf_secret(),
        f"{session_id or 'anonymous'}:{nonce}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected_mac, provided_mac)


def resolve_request_session(request: Request) -> Optional[dict[str, Any]]:
    """Resolve authenticated session via Model host internal introspection.

    Returns None when unauthenticated (no cookie or invalid cookie).
    Raises IntrospectionUnavailableError when authority is configured and unreachable/malformed.
    """
    session_cookie = request.cookies.get(COOKIE_NAME)
    demo_cookie = request.cookies.get(DEMO_COOKIE_NAME)
    if not session_cookie and not demo_cookie:
        return None

    introspector = getattr(request.app.state, "introspector", None) or introspect_with_model_host
    verdict: IntrospectedSession = introspector(session_cookie, demo_cookie)
    if not verdict.authenticated:
        return None
    return {
        "session_kind": verdict.session_kind,
        "user_id": verdict.user_id,
        "subject_id": verdict.user_id,
        "tenant_id": verdict.tenant_id,
        "entitlements": list(verdict.entitlements),
        "entitlement_decisions": dict(verdict.entitlement_decisions or {}),
        "wallet_verified": verdict.wallet_verified,
        "wallet_address": verdict.wallet_address,
    }


def wallet_context_for_session(session: Optional[Mapping[str, Any]]) -> WalletContext:
    if not session:
        return WalletContext()
    verified = bool(session.get("wallet_verified", False))
    addr = session.get("wallet_address")
    return WalletContext(
        subject_id=session.get("user_id") or session.get("subject_id"),
        verified=verified,
        wallet_address=addr if isinstance(addr, str) else None,
        entitlements=tuple(session.get("entitlements") or ()),
        entitlement_decisions=session.get("entitlement_decisions"),
        authority_error=bool(session.get("authority_error", False)),
    )


def get_verified_wallet(session: Optional[Mapping[str, Any]]) -> Optional[str]:
    ctx = wallet_context_for_session(session)
    return ctx.wallet_address if ctx.verified else None


def get_wallet_state(request: Any, session: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
    ctx = wallet_context_for_session(session)
    return {
        "connected": bool(ctx.wallet_address),
        "verified": ctx.verified,
        "address": ctx.wallet_address,
        "status": "VERIFIED" if ctx.verified and ctx.wallet_address else ("CONNECTED" if ctx.wallet_address else "UNAVAILABLE"),
    }


def build_crypto_access_snapshot(
    wallet_state: Any,
    session: Optional[Mapping[str, Any]] = None,
    *,
    resource_decisions: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    wstate = wallet_state if isinstance(wallet_state, Mapping) else get_wallet_state(wallet_state, session)
    serialized_decisions = {}
    for k, v in (resource_decisions or {}).items():
        if isinstance(v, ResourceAccessDecision):
            serialized_decisions[k] = {
                "decision": v.decision.value,
                "reason_code": v.reason_code,
                "authority_available": v.authority_available,
            }
        elif isinstance(v, Mapping):
            serialized_decisions[k] = dict(v)
    return {
        "authenticated": bool(session) or bool(wstate.get("connected")),
        "wallet": dict(wstate),
        "token_gating_active": _token_gating_active(),
        "token_configured": _token_deployment_configured(),
        "resources": serialized_decisions,
    }


def _evaluate_sync(resource: str, wallet: Optional[WalletContext] = None) -> ResourceAccessDecision:
    if resource in PUBLIC_RESOURCES:
        return ResourceAccessDecision(
            resource=resource,
            decision=Decision.ALLOW,
            reason_code="PUBLIC_RESOURCE",
            wallet_address=wallet.wallet_address if wallet else None,
            authority_available=True,
        )

    if resource not in HOLDER_RESOURCES:
        return ResourceAccessDecision(
            resource=resource,
            decision=Decision.DENY,
            reason_code="UNKNOWN_RESOURCE",
            wallet_address=None,
            authority_available=True,
        )

    if wallet and wallet.authority_error:
        return ResourceAccessDecision(
            resource=resource,
            decision=Decision.DENY,
            reason_code="ENTITLEMENT_AUTHORITY_UNAVAILABLE",
            wallet_address=None,
            authority_available=False,
        )

    # Honor explicit authoritative server-side decision from Model host
    if wallet and isinstance(wallet.entitlement_decisions, Mapping) and resource in wallet.entitlement_decisions:
        server_dec = wallet.entitlement_decisions[resource]
        if isinstance(server_dec, Mapping):
            dec_raw = server_dec.get("decision")
            if dec_raw == "PUBLIC":
                return ResourceAccessDecision(
                    resource=resource,
                    decision=Decision.ALLOW,
                    reason_code="PUBLIC_RESOURCE",
                    wallet_address=wallet.wallet_address,
                    authority_available=True,
                )
            if dec_raw in {d.value for d in Decision}:
                return ResourceAccessDecision(
                    resource=resource,
                    decision=Decision(dec_raw),
                    reason_code=str(server_dec.get("reason", "AUTHORITY_DECISION")),
                    wallet_address=wallet.wallet_address,
                    authority_available=True,
                    feature_active=_token_gating_active(),
                    token_configured=_token_deployment_configured(),
                )
        # Malformed server decision entry -> fail closed
        return ResourceAccessDecision(
            resource=resource,
            decision=Decision.DENY,
            reason_code="ENTITLEMENT_AUTHORITY_UNAVAILABLE",
            wallet_address=None,
            authority_available=False,
        )

    # If Model authority is configured OR running in staging/production, missing per-resource decision MUST fail closed
    if _authority_configured() or os.getenv("FINCO_ENV", "").strip().lower() in ("prod", "production", "staging"):
        return ResourceAccessDecision(
            resource=resource,
            decision=Decision.DENY,
            reason_code="ENTITLEMENT_AUTHORITY_UNAVAILABLE",
            wallet_address=wallet.wallet_address if wallet else None,
            authority_available=False,
        )

    # Local offline/test fallback when Model authority is not configured
    feature_active = _token_gating_active()
    token_configured = _token_deployment_configured()
    addr = wallet.wallet_address if wallet else None

    if not feature_active:
        return ResourceAccessDecision(
            resource=resource,
            decision=Decision.INACTIVE,
            reason_code="TOKEN_ENTITLEMENT_FEATURE_INACTIVE",
            wallet_address=addr,
            authority_available=True,
            feature_active=False,
            token_configured=token_configured,
        )

    if not token_configured:
        return ResourceAccessDecision(
            resource=resource,
            decision=Decision.DENY,
            reason_code="TOKEN_DEPLOYMENT_NOT_CONFIGURED",
            wallet_address=addr,
            authority_available=True,
            feature_active=True,
            token_configured=False,
        )

    if not wallet or not wallet.subject_id:
        return ResourceAccessDecision(
            resource=resource,
            decision=Decision.DENY,
            reason_code="WALLET_UNAVAILABLE",
            wallet_address=None,
            authority_available=True,
            feature_active=True,
            token_configured=True,
        )

    if resource == "yield.execution_preflight" and not wallet.verified:
        return ResourceAccessDecision(
            resource=resource,
            decision=Decision.DENY,
            reason_code="WALLET_UNVERIFIED",
            wallet_address=addr,
            authority_available=True,
            feature_active=True,
            token_configured=True,
        )

    if resource in wallet.entitlements:
        return ResourceAccessDecision(
            resource=resource,
            decision=Decision.ALLOW,
            reason_code="HOLDER_ENTITLED",
            wallet_address=addr,
            authority_available=True,
            feature_active=True,
            token_configured=True,
        )

    return ResourceAccessDecision(
        resource=resource,
        decision=Decision.DENY,
        reason_code="ENTITLEMENT_NOT_SATISFIED",
        wallet_address=addr,
        authority_available=True,
        feature_active=True,
        token_configured=True,
    )


async def evaluate_resource_access(
    resource: str,
    wallet: Optional[WalletContext] = None,
) -> ResourceAccessDecision:
    return _evaluate_sync(resource, wallet)


async def evaluate_all_resources(
    wallet: Optional[WalletContext] = None,
) -> dict[str, ResourceAccessDecision]:
    return {res: _evaluate_sync(res, wallet) for res in sorted(PUBLIC_RESOURCES | HOLDER_RESOURCES)}
