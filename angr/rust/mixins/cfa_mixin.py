# Compatibility shim: the mixin lives in angr.analyses.decompiler.mixins now.
from __future__ import annotations

from angr.analyses.decompiler.mixins.cfa_mixin import CFAMixin

__all__ = ["CFAMixin"]
