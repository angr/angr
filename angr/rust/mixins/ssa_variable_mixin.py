# Compatibility shim: the mixin lives in angr.analyses.decompiler.mixins now.
from __future__ import annotations

from angr.analyses.decompiler.mixins.ssa_variable_mixin import SSAVariableMixin

__all__ = ["SSAVariableMixin"]
