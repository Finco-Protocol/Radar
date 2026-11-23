"""Standalone v1.1 institutional read-only envelope schemas for FINCO Radar."""
from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict

API_VERSION = "v1.1"
SCHEMA_VERSION = "institutional-v1.1.0"


class ApiErrorEnvelope(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    api_version: str = API_VERSION
    schema_version: str = SCHEMA_VERSION
    error: str
    detail: str
    project_id: Optional[str] = None


class InstitutionalEnvelope(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    api_version: str = API_VERSION
    schema_version: str = SCHEMA_VERSION
    state: str
    project_id: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    evidence: Optional[Dict[str, Any]] = None
