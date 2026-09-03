# Compatibility shim: the mixin lives in angr.analyses.decompiler.mixins now.
from __future__ import annotations

from angr.analyses.decompiler.mixins.srda_mixin import SRDAMixin

__all__ = ["SRDAMixin"]
