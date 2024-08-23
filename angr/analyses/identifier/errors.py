from __future__ import annotations
from ...errors import AngrAnalysisError


class IdentifierException(AngrAnalysisError):
    pass


class FunctionNotInitialized(AngrAnalysisError):
    pass
