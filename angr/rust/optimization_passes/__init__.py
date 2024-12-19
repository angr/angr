from .callsite_simplifier import CallsiteSimplifier
from .calling_convention_recovery import CallingConventionRecovery
from .callsite_corrector import CallsiteCorrector
from .cleanup_code_remover import CleanupCodeRemover
from .deref_coercion_simplifier import DerefCoercionSimplifier
from .pattern_match_identifier import PatternMatchIdentifier
from .pattern_match_simplifier import PatternMatchSimplifier
from .lifetime_simplifier import LifetimeSimplifier
from .macro.print_macro_simplifier import PrintMacroSimplifier
from .ret_site_simplifier import RetSiteSimplifier
from .security_check_remover import SecurityCheckRemover
from .str_argument_simplifier import StrArgumentSimplifier
from .struct_field_access_simplifier import StructFieldAccessSimplifier
from .struct_return_simplifier import StructReturnSimplifier
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
        PatternMatchIdentifier,
        OwnershipSimplifier,
        StructInstantiationSimplifier,
        PrintMacroSimplifier,
        SecurityCheckRemover,
        # StructFieldAccessSimplifier,
        DerefCoercionSimplifier,
        # AFTER_VARIABLE_RECOVERY
        TypeCorrector,
        StrArgumentSimplifier,
        # AFTER_STRUCTURING
        PatternMatchSimplifier,
        StructReturnSimplifier,
    ]
