from __future__ import annotations
from angr.errors import AngrAnalysisError


class IdentifierException(AngrAnalysisError):
    pass


class FunctionNotInitialized(AngrAnalysisError):
    pass
