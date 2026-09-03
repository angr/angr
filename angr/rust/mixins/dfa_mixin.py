# Compatibility shim: the mixin lives in angr.analyses.decompiler.mixins now.
from __future__ import annotations

from angr.analyses.decompiler.mixins.dfa_mixin import DFAMixin

__all__ = ["DFAMixin"]
