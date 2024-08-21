from .calling_convention_recovery import CallingConventionRecovery
from .error_handling_simplifier import ErrorHandlingSimplifier
from .lifetime_simplifier import LifetimeSimplifier
from .ret_site_simplifier import RetSiteSimplifier
from ...analyses.decompiler.optimization_passes import _all_optimization_passes, ReturnDuplicatorLow
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
        # Before type recovery
        (LibFunctionIdentifier, True),
        (EpilogueSimplifier, True),
        (ErrorHandlingSimplifier, True),
        (RetSiteSimplifier, True),
        # (CallingConventionRecovery, True),
        (OwnershipSimplifier, True),
        (AllocSimplifier, True),
        # After type recovery
        (StructInstantiationSimplifier, True),
        (UnwrapSimplifier, True),
        (LifetimeSimplifier, True),
        # (StringSimplifier, True),
        # (TypeCorrector, True),
    ]
)
