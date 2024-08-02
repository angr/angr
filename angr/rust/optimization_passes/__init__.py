from ...analyses.decompiler.optimization_passes import _all_optimization_passes
from .unwrap_simplifier import UnwrapSimplifier
from .lib_function_identifier import LibFunctionIdentifier
from .string_simplifier import StringSimplifier
from .junk_remover import JunkRemover
from .alloc_simplifier import AllocSimplifier
from .type_corrector import TypeCorrector
from .callsite_maker import CallsiteMaker
from .ownership_simplifier import OwnershipSimplifier

_all_optimization_passes.extend(
    [
        (LibFunctionIdentifier, True),
        (JunkRemover, True),
        (CallsiteMaker, True),
        (UnwrapSimplifier, True),
        # (StringSimplifier, True),
        (AllocSimplifier, True),
        # (TypeCorrector, True),
        (OwnershipSimplifier, True),
    ]
)
