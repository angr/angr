from ...analyses.decompiler.optimization_passes import _all_optimization_passes
from .lib_function_identifier import LibFunctionIdentifier
from .string_simplifier import StringSimplifier
from .junk_remover import JunkRemover
from .alloc_simplifier import AllocSimplifier
from .type_corrector import TypeCorrector

_all_optimization_passes.extend(
    [
        (LibFunctionIdentifier, True),
        (JunkRemover, True),
        (StringSimplifier, True),
        (AllocSimplifier, True),
        (TypeCorrector, True),
    ]
)
