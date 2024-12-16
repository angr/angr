# deobfuscator is a collection of analyses that automatically identifies functions where obfuscation techniques are
# in-use.
from __future__ import annotations

from .string_obf_finder import StringObfuscationFinder
from .string_obf_peephole_optimizer import StringObfType1PeepholeOptimizer
from .string_obf_opt_passes import StringObfType3Rewriter
from .api_obf_finder import APIObfuscationFinder
from .api_obf_peephole_optimizer import APIObfType1PeepholeOptimizer


__all__ = (
    "APIObfType1PeepholeOptimizer",
    "APIObfuscationFinder",
    "StringObfType1PeepholeOptimizer",
    "StringObfType3Rewriter",
    "StringObfuscationFinder",
)
