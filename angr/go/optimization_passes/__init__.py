from __future__ import annotations

from .arg_spill_remover import GoArgSpillRemover
from .pinned_register_namer import GoPinnedRegisterNamer
from .pinned_register_rewriter import GoPinnedRegisterRewriter
from .stack_check_remover import GoStackCheckRemover


def get_go_optimization_passes():
    return [
        # BEFORE_SSA_LEVEL0_TRANSFORMATION
        GoStackCheckRemover,
        GoPinnedRegisterRewriter,
        # BEFORE_VARIABLE_RECOVERY
        GoArgSpillRemover,
        # AFTER_VARIABLE_RECOVERY
        GoPinnedRegisterNamer,
    ]
