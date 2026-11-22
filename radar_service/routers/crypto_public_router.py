"""Standalone Crypto Tokenized & Yield Public API router backed by finco_radar + finco_yield."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from finco_radar.venues.seed_loader import load_seed
from finco_yield.registry import load_bundled_registry

router = APIRouter(tags=["crypto-public"])


@router.get("/api/v1/crypto/tokenized")
def list_tokenized_assets() -> JSONResponse:
    seed = load_seed()
    reps = seed.get("representations", [])
    return JSONResponse({
        "schema": "finco.crypto.tokenized.v1",
        "count": len(reps),
        "items": reps,
    })


@router.get("/api/v1/crypto/tokenized/{canonical_asset_id}")
def get_tokenized_asset(canonical_asset_id: str) -> JSONResponse:
    seed = load_seed()
    reps = seed.get("representations", [])
    needle = canonical_asset_id.lower()
    matches = [
        r for r in reps
        if needle in (
            str(r.get("canonical_asset_id", "")).lower(),
            str(r.get("representation_symbol", "")).lower(),
            str(r.get("underlying_symbol", "")).lower(),
        )
    ]
    if not matches:
        raise HTTPException(status_code=404, detail="Unknown tokenized asset")
    return JSONResponse({
        "schema": "finco.crypto.tokenized.detail.v1",
        "canonical_asset_id": canonical_asset_id,
        "venues": matches,
    })


@router.get("/api/v1/crypto/yield")
def list_crypto_yield() -> JSONResponse:
    opps = load_bundled_registry().all()
    items = [
        {
            "opportunity_uid": o.uid,
            "name": o.name,
            "protocol": o.protocol,
            "asset": o.underlying_symbol,
            "chain_id": o.chain_id,
            "data_origin": o.data_origin,
        }
        for o in opps
    ]
    return JSONResponse({
        "schema": "finco.crypto.yield.v1",
        "count": len(items),
        "items": items,
    })


@router.get("/api/v1/crypto/yield/{canonical_id}")
def get_crypto_yield(canonical_id: str) -> JSONResponse:
    opps = load_bundled_registry().all()
    for o in opps:
        if o.uid == canonical_id:
            return JSONResponse({
                "schema": "finco.crypto.yield.detail.v1",
                "opportunity_uid": o.uid,
                "name": o.name,
                "protocol": o.protocol,
                "asset": o.underlying_symbol,
                "chain_id": o.chain_id,
                "data_origin": o.data_origin,
            })
    raise HTTPException(status_code=404, detail="Unknown yield opportunity")
