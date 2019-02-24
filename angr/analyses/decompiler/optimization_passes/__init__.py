
from .stack_canary_simplifier import StackCanarySimplifier
from .return_address_save_simplifier import ReturnAddressSaveSimplifier


_all_optimization_passes = [
    StackCanarySimplifier,
    ReturnAddressSaveSimplifier,
]


def get_optimization_passes(arch, platform):

    import archinfo

    if isinstance(arch, archinfo.Arch):
        arch = arch.name

    platform = platform.lower()

    passes = [ ]
    for pass_ in _all_optimization_passes:
        if arch in pass_.ARCHES and platform in pass_.PLATFORMS:
            passes.append(pass_)

    return passes
