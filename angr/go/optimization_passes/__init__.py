from __future__ import annotations

from .arg_spill_remover import GoArgSpillRemover
from .builtin_rewriter import GoBuiltinRewriter
from .check_remover import GoCheckRemover
from .descriptor_namer import GoDescriptorNamer
from .global_types import GoGlobalTypes
from .multi_value import GoComboRegisterRewriter, GoRetExprRewriter
from .parameter_types import GoParameterTypes
from .pinned_register_namer import GoPinnedRegisterNamer
from .pinned_register_rewriter import GoPinnedRegisterRewriter
from .prototypes import GoPrototypes
from .runtime_rewriter import GoRuntimeRewriter
from .stack_check_remover import GoStackCheckRemover
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
        # BEFORE_VARIABLE_RECOVERY
        GoParameterTypes,
        GoGlobalTypes,
        GoComboRegisterRewriter,
        GoArgSpillRemover,
        GoValueFuser,
        GoRuntimeRewriter,
        GoBuiltinRewriter,
        # AFTER_VARIABLE_RECOVERY
        GoPinnedRegisterNamer,
        GoDescriptorNamer,
    ]
