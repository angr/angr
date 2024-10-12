from .callsite_simplifier import CallsiteSimplifier
from .calling_convention_recovery import CallingConventionRecovery
from .callsite_corrector import CallsiteCorrector
from .cleanup_code_remover import CleanupCodeRemover
from .error_handling_simplifier import ErrorHandlingSimplifier
from .lifetime_simplifier import LifetimeSimplifier
from .ret_site_simplifier import RetSiteSimplifier
from .unwrap_simplifier import UnwrapSimplifier
from .lib_function_identifier import LibFunctionIdentifier
from .alloc_simplifier import AllocSimplifier
from .type_corrector import TypeCorrector
from .struct_instantiation_simplifier import StructInstantiationSimplifier
from .ownership_simplifier import OwnershipSimplifier


def get_rust_optimization_passes():
    return [
        # AFTER_SINGLE_BLOCK_SIMPLIFICATION
        LibFunctionIdentifier,
        # AFTER_GLOBAL_SIMPLIFICATION
        CleanupCodeRemover,
        AllocSimplifier,
        CallsiteSimplifier,
        CallsiteCorrector,
        UnwrapSimplifier,
        OwnershipSimplifier,
        StructInstantiationSimplifier,
        # AFTER_VARIABLE_RECOVERY
        TypeCorrector,
    ]
