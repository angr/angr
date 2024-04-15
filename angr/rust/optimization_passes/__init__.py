from ...analyses.decompiler.optimization_passes import _all_optimization_passes
from .string_simplifier import StringSimplifier
from .alloc_simplifier import AllocSimplifier
from .type_corrector import TypeCorrector
from .dealloc_simplifier import DeallocSimplifier

_all_optimization_passes.extend(
    [(StringSimplifier, True), (AllocSimplifier, True), (DeallocSimplifier, True), (TypeCorrector, True)]
)
