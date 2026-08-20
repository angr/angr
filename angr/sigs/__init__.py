# This submodule suggests and applies function signatures for statically linked libraries
from __future__ import annotations

from .sigserv_client import SIGSERV_PROTOCOL_VERSION, SigservClient
from .suggest_signature import SuggestSignatureAnalysis, collect_query_integers, collect_query_strings

__all__ = [
    "SIGSERV_PROTOCOL_VERSION",
    "SigservClient",
    "SuggestSignatureAnalysis",
    "collect_query_integers",
    "collect_query_strings",
]
