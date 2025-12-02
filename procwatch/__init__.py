"""
ProcWatch — Linux process anomaly detection engine
with heuristics, machine learning, and live response.

CLI entry: procwatch (see pyproject.toml)
"""

from .models import ProcInfo, Suspicion
from .heuristics import HeuristicScorer
from .ml import choose_model
from .features import extract_features

__all__ = [
    "ProcInfo",
    "Suspicion",
    "HeuristicScorer",
    "choose_model",
    "extract_features",
]

__version__ = "3.0.0"
