# Compatibility shims: the language-neutral mixins live in angr.analyses.decompiler.mixins now.
from __future__ import annotations

from angr.analyses.decompiler.mixins import CFAMixin, CFGTransformationMixin, DFAMixin, SRDAMixin, SSAVariableMixin

__all__ = [
    "CFAMixin",
    "CFGTransformationMixin",
    "DFAMixin",
    "SRDAMixin",
    "SSAVariableMixin",
]
