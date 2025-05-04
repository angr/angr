from .error_propagation_simplifier import ErrorPropagationSimplifier
from .function_prototype_inference import FunctionPrototypeInference
from .cleanup_code_remover import CleanupCodeRemover
from .deref_coercion_simplifier import DerefCoercionSimplifier
from .macro.show_macro_simplifier import ShowMacroSimplifier
from .macro.vec_macro_simplifier import VecMacroSimplifier
from .outliners.string_cmp_outliner import StringCmpOutliner
from .outliners.string_outliner import StringOutliner
from .pattern_match_simplifier import PatternMatchSimplifier
from .macro.print_macro_simplifier import PrintMacroSimplifier
from .pre_pattern_match_simplifier import PrePatternMatchSimplifier
from .ret_expr_rewriter import RetExprRewriter
from .security_check_remover import SecurityCheckRemover
from .str_argument_simplifier import StrArgumentSimplifier
from .struct_return_simplifier import StructReturnSimplifier
from .unwrap_simplifier import UnwrapSimplifier
from .alloc_simplifier import AllocSimplifier
from .type_corrector import TypeCorrector
from .struct_instantiation_simplifier import StructInstantiationSimplifier
from .ownership_simplifier import OwnershipSimplifier


def get_rust_optimization_passes():
    return [
        # BEFORE_SSA_LEVEL0_TRANSFORMATION
        RetExprRewriter,
        # BEFORE_VARIABLE_RECOVERY
        # CleanupCodeRemover,
        # SecurityCheckRemover,
        FunctionPrototypeInference,
        UnwrapSimplifier,
        StrArgumentSimplifier,
        StructInstantiationSimplifier,
        StringOutliner,
        StringCmpOutliner,
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
