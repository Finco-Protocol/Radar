"""Read-only versioned Model <-> Market Bridge v1 contract and HTTP reader.

Strict boundary guarantees:
- Read-only consumption of Model public/signed verification artifacts only:
  - GET /.well-known/finco/keys.json
  - GET /api/v1.1/runs/{run_id}/certificate
- Zero financial math, zero Model DB access, zero Model state mutation.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import httpx

BRIDGE_CONTRACT_V1 = {
    "schema": "finco.radar.bridge_contract.v1",
    "mode": "READ_ONLY",
    "model_authority_endpoints": [
        "GET /.well-known/finco/keys.json",
        "GET /api/v1.1/runs/{run_id}/certificate",
    ],
    "radar_mutations_allowed": False,
    "financial_math_in_radar": False,
    "shared_contract_package": "finco-evidence-envelope==0.1.0",
    "shared_envelope_schema": "finco.evidence-envelope.v1",
}


class BridgeUnavailableError(RuntimeError):
    """Raised when the Model read-only bridge upstream is unconfigured or unreachable."""


def fetch_model_public_keys(
    *,
    base_url: Optional[str] = None,
    timeout_seconds: float = 3.0,
) -> dict[str, Any]:
    """Read Model host public JWKS/verification keys via read-only HTTP GET."""
    resolved = (base_url or os.getenv("FINCO_MODEL_PUBLIC_URL") or os.getenv("FINCO_MODEL_INTERNAL_AUTH_URL", "")).strip().rstrip("/")
    if not resolved:
        raise BridgeUnavailableError("Model bridge base URL is not configured")
    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            resp = client.get(f"{resolved}/.well-known/finco/keys.json")
    except httpx.HTTPError as exc:
        raise BridgeUnavailableError("Model bridge unreachable") from exc
    if resp.status_code != 200:
        raise BridgeUnavailableError(f"Model bridge returned HTTP {resp.status_code}")
    data = resp.json()
    if not isinstance(data, dict):
        raise BridgeUnavailableError("Model bridge returned malformed JSON object")
    return data


def fetch_model_run_certificate(
    run_id: str,
    *,
    base_url: Optional[str] = None,
    timeout_seconds: float = 3.0,
) -> dict[str, Any]:
    """Read signed run certificate from Model host via read-only HTTP GET."""
    if not run_id or "/" in run_id or ".." in run_id:
        raise ValueError("Invalid run_id")
    resolved = (base_url or os.getenv("FINCO_MODEL_PUBLIC_URL") or os.getenv("FINCO_MODEL_INTERNAL_AUTH_URL", "")).strip().rstrip("/")
    if not resolved:
        raise BridgeUnavailableError("Model bridge base URL is not configured")
    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            resp = client.get(f"{resolved}/api/v1.1/runs/{run_id}/certificate")
    except httpx.HTTPError as exc:
        raise BridgeUnavailableError("Model bridge unreachable") from exc
    if resp.status_code != 200:
        raise BridgeUnavailableError(f"Model certificate endpoint returned HTTP {resp.status_code}")
    data = resp.json()
    if not isinstance(data, dict):
        raise BridgeUnavailableError("Model certificate endpoint returned malformed JSON")
    return data
