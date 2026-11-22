"""Frozen read-only Model <-> Market Bridge v1 contract descriptor (Radar consumer side).

Proves zero financial calculation logic is delegated to Radar and zero Model
mutations are permitted across the service boundary.
"""
from __future__ import annotations

BRIDGE_CONTRACT_V1 = {
    "schema": "finco.model-market-bridge.contract.v1",
    "mode": "READ_ONLY",
    "mutations_permitted": False,
    "financial_math_owner": "FincoProtocol",
    "market_intelligence_owner": "FincoRadar",
    "shared_verification_envelope": "finco.evidence-envelope.v1",
    "canonicalization": "FINCO_SORTED_JSON_V1",
}
