from __future__ import annotations

from .arg_spill_remover import GoArgSpillRemover
from .boxing_rewriter import GoBoxingRewriter
from .builtin_rewriter import GoBuiltinRewriter
from .check_remover import GoCheckRemover
from .closure_context import GoClosureContextNamer
from .descriptor_namer import GoDescriptorNamer
from .global_types import GoGlobalTypes
from .header_word_types import GoHeaderWordTypes
from .multi_value import GoComboRegisterRewriter, GoRetExprRewriter
from .parameter_types import GoParameterTypes
from .pinned_register_namer import GoPinnedRegisterNamer
from .pinned_register_rewriter import GoPinnedRegisterRewriter
from .prototype_inference import GoPrototypeInference
from .prototypes import GoPrototypes
from .result_widener import GoResultWidener
from .runtime_rewriter import GoRuntimeRewriter
from .stack_check_remover import GoStackCheckRemover
from .type_switch_simplifier import GoTypeSwitchSimplifier
from .value_fuser import GoValueFuser


def get_go_optimization_passes():
    return [
        # AFTER_AIL_GRAPH_CREATION
        GoPrototypes,
        # BEFORE_SSA_LEVEL0_TRANSFORMATION
        GoStackCheckRemover,
        GoCheckRemover,
        GoPinnedRegisterRewriter,
        GoRetExprRewriter,
        GoResultWidener,
        # BEFORE_VARIABLE_RECOVERY
        GoParameterTypes,
        GoGlobalTypes,
        GoComboRegisterRewriter,
        GoArgSpillRemover,
        GoTypeSwitchSimplifier,
        GoValueFuser,
        GoRuntimeRewriter,
        GoBuiltinRewriter,
        GoBoxingRewriter,
        GoHeaderWordTypes,
        GoPrototypeInference,
        # AFTER_VARIABLE_RECOVERY
        GoPinnedRegisterNamer,
        GoClosureContextNamer,
        GoDescriptorNamer,
    ]
