from .error_propagation_simplifier import ErrorPropagationSimplifier
from .function_prototype_inference import FunctionPrototypeInference
from .cleanup_code_remover import CleanupCodeRemover
from .deref_coercion_simplifier import DerefCoercionSimplifier
from .macro.show_macro_simplifier import ShowMacroSimplifier
from .macro.vec_macro_simplifier import VecMacroSimplifier
from .outliners.string_outliner import StringOutliner
from .pattern_match_identifier import PatternMatchIdentifier
from .pattern_match_simplifier import PatternMatchSimplifier
from .macro.print_macro_simplifier import PrintMacroSimplifier
from .pre_pattern_match_simplifier import PrePatternMatchSimplifier
from .security_check_remover import SecurityCheckRemover
from .str_argument_simplifier import StrArgumentSimplifier
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
        # LibFunctionIdentifier,
        # AFTER_GLOBAL_SIMPLIFICATION
        CleanupCodeRemover,
        SecurityCheckRemover,
        # AllocSimplifier,  # Maybe useless when inlining is disabled
        FunctionPrototypeInference,
        UnwrapSimplifier,
        StrArgumentSimplifier,
        # RUST_SPECIFIC_SIMPLIFICATION
        # PatternMatchIdentifier,
        OwnershipSimplifier,
        StructInstantiationSimplifier,
        StringOutliner,
        PrintMacroSimplifier,
        VecMacroSimplifier,
        ShowMacroSimplifier,
        DerefCoercionSimplifier,
        StructReturnSimplifier,
        PrePatternMatchSimplifier,
        # AFTER_VARIABLE_RECOVERY
        TypeCorrector,
        # AFTER_STRUCTURING
        PatternMatchSimplifier,
        ErrorPropagationSimplifier,
    ]
