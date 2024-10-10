from .callsite_simplifier import CallsiteSimplifier
from .calling_convention_recovery import CallingConventionRecovery
from .callsite_corrector import CallsiteCorrector
from .cleanup_code_remover import CleanupCodeRemover
from .drop_simplifier import DropSimplifier
from .error_handling_simplifier import ErrorHandlingSimplifier
from .lifetime_simplifier import LifetimeSimplifier
from .ret_site_simplifier import RetSiteSimplifier
from ...analyses.decompiler.optimization_passes import ALL_OPTIMIZATION_PASSES, ReturnDuplicatorLow
from .unwrap_simplifier import UnwrapSimplifier
from .lib_function_identifier import LibFunctionIdentifier
from .string_simplifier import StringSimplifier
from .epilogue_simplifier import EpilogueSimplifier
from .alloc_simplifier import AllocSimplifier
from .type_corrector import TypeCorrector
from .struct_instantiation_simplifier import StructInstantiationSimplifier
from .ownership_simplifier import OwnershipSimplifier


def get_rust_optimization_passes():
    return [
        # AFTER_SINGLE_BLOCK_SIMPLIFICATION
        LibFunctionIdentifier,
        # (CallSiteSimplifier, True),
        # (EpilogueSimplifier, True),
        # (ErrorHandlingSimplifier, True),
        # (RetSiteSimplifier, True),
        # (CallingConventionRecovery, True),
        AllocSimplifier,
        # AFTER_MAKING_CALLSITES
        CallsiteSimplifier,
        CallsiteCorrector,
        # AFTER_GLOBAL_SIMPLIFICATION
        UnwrapSimplifier,
        OwnershipSimplifier,
        StructInstantiationSimplifier,
        CleanupCodeRemover,
        # (LifetimeSimplifier, True),
        # (StringSimplifier, True),
        # AFTER_VARIABLE_RECOVERY
        TypeCorrector,
        # AFTER_STRUCTURING
        # (DropSimplifier, True),
    ]
