"""FINCO Radar Economy — read-only macro/economic intelligence surface."""
from radar_service.economy.contracts import (
    EconomyObservation,
    EconomySection,
    EconomySeriesDefinition,
    EconomyState,
    EconomyTransform,
)
from radar_service.economy.registry import SERIES, get_series, series_for_section
from radar_service.economy.service import EconomyDashboardService

__all__ = [
    "EconomyDashboardService",
    "EconomyObservation",
    "EconomySection",
    "EconomySeriesDefinition",
    "EconomyState",
    "EconomyTransform",
    "SERIES",
    "get_series",
    "series_for_section",
]
