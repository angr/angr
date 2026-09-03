from __future__ import annotations

from .arg_spill_remover import GoArgSpillRemover
from .multi_value import GoComboRegisterRewriter, GoRetExprRewriter
from .parameter_types import GoParameterTypes
from .pinned_register_namer import GoPinnedRegisterNamer
from .pinned_register_rewriter import GoPinnedRegisterRewriter
from .prototypes import GoPrototypes
from .stack_check_remover import GoStackCheckRemover
from .value_fuser import GoValueFuser


def get_go_optimization_passes():
    return [
        # AFTER_AIL_GRAPH_CREATION
        GoPrototypes,
        # BEFORE_SSA_LEVEL0_TRANSFORMATION
        GoStackCheckRemover,
        GoPinnedRegisterRewriter,
        GoRetExprRewriter,
        # BEFORE_VARIABLE_RECOVERY
        GoParameterTypes,
        GoComboRegisterRewriter,
        GoArgSpillRemover,
        GoValueFuser,
        # AFTER_VARIABLE_RECOVERY
        GoPinnedRegisterNamer,
    ]
