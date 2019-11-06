
from .stack_canary_simplifier import StackCanarySimplifier
from .base_ptr_save_simplifier import BasePointerSaveSimplifier
from .multi_simplifier import MultiSimplifier
from .div_simplifier import DivSimplifier
from .mod_simplifier import ModSimplifier


_all_optimization_passes = [
    StackCanarySimplifier,
    BasePointerSaveSimplifier,
    DivSimplifier,
    MultiSimplifier,
    ModSimplifier
]


def get_optimization_passes(arch, platform):

    import archinfo

    # sanity check
    if platform is None:
        return [ ]

    if isinstance(arch, archinfo.Arch):
        arch = arch.name

    platform = platform.lower()

    passes = [ ]
    for pass_ in _all_optimization_passes:
        if arch in pass_.ARCHES and platform in pass_.PLATFORMS:
            passes.append(pass_)

    return passes
