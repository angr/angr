from __future__ import annotations

from .cleanup_code_remover import CleanupCodeRemover
from .combo_register_rewriter import ComboRegisterRewriter
from .deref_coercion_simplifier import DerefCoercionSimplifier
from .deref_coercion_simplifier_uninlined import DerefCoercionSimplifierUninlined
from .error_propagation_simplifier import ErrorPropagationSimplifier
from .function_prototype_inference import FunctionPrototypeInference
from .macro.format_macro_simplifier import FormatMacroSimplifier
from .outliners.string_cmp_outliner import StringCmpOutliner
from .outliners.string_literal_outliner import StringLiteralOutliner
from .outliners.string_outliner import StringOutliner
from .outliners.unwrap_outliner import UnwrapOutliner
from .outliners.vec_outliner import VecOutliner
from .pattern_match_simplifier import PatternMatchSimplifier
from .pre_pattern_match_simplifier import PrePatternMatchSimplifier
from .redundant_block_remover import RedundantBlockRemover
from .ret_expr_rewriter import RetExprRewriter
from .rust_calling_convention import RustCallingConvention
from .security_check_remover import SecurityCheckRemover
from .str_argument_simplifier import StrArgumentSimplifier
from .struct_instantiation_simplifier import StructInstantiationSimplifier
from .struct_return_simplifier import StructReturnSimplifier


def get_rust_optimization_passes():
    return [
        # BEFORE_SSA_LEVEL0_TRANSFORMATION
        RustCallingConvention,
        RetExprRewriter,
        # BEFORE_VARIABLE_RECOVERY
        ComboRegisterRewriter,
        CleanupCodeRemover,
        SecurityCheckRemover,
        FunctionPrototypeInference,
        StructInstantiationSimplifier,
        StringOutliner,
        VecOutliner,
        StringCmpOutliner,
        StringLiteralOutliner,
        UnwrapOutliner,
        FormatMacroSimplifier,
        DerefCoercionSimplifier,
        StructReturnSimplifier,
        PrePatternMatchSimplifier,
        # AFTER_VARIABLE_RECOVERY
        StrArgumentSimplifier,
        DerefCoercionSimplifierUninlined,
        # BEFORE_REGION_IDENTIFICATION
        RedundantBlockRemover,
        # AFTER_STRUCTURING
        PatternMatchSimplifier,
        ErrorPropagationSimplifier,
    ]
