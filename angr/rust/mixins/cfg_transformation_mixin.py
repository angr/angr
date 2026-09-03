# Compatibility shim: the mixin lives in angr.analyses.decompiler.mixins now.
from __future__ import annotations

from angr.analyses.decompiler.mixins.cfg_transformation_mixin import CFGTransformationMixin

__all__ = ["CFGTransformationMixin"]
