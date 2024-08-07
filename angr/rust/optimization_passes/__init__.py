from .error_handling_simplifier import ErrorHandlingSimplifier
from .lifetime_simplifier import LifetimeSimplifier
from ...analyses.decompiler.optimization_passes import _all_optimization_passes
from .unwrap_simplifier import UnwrapSimplifier
from .lib_function_identifier import LibFunctionIdentifier
from .string_simplifier import StringSimplifier
from .epilogue_simplifier import EpilogueSimplifier
from .alloc_simplifier import AllocSimplifier
from .type_corrector import TypeCorrector
from .struct_instantiation_simplifier import StructInstantiationSimplifier
from .ownership_simplifier import OwnershipSimplifier

_all_optimization_passes.extend(
    [
        (LibFunctionIdentifier, True),
        (StructInstantiationSimplifier, True),
        (EpilogueSimplifier, True),
        (ErrorHandlingSimplifier, True),
        (UnwrapSimplifier, True),
        (LifetimeSimplifier, True),
        # (StringSimplifier, True),
        (AllocSimplifier, True),
        # (TypeCorrector, True),
        (OwnershipSimplifier, True),
    ]
)
