from ...analyses.decompiler.optimization_passes import _all_optimization_passes
from .vec_simplifier import VecSimplifier
from .string_simplifier import StringSimplifier
from .alloc_simplifier import AllocSimplifier

_all_optimization_passes.extend([(StringSimplifier, True), (AllocSimplifier, True)])
