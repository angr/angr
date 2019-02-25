
from .base_ptr_save_simplifier import BasePointerSaveSimplifier
from .empty_conditional_simplifier import EmptyConditionalSimplifier
from .optimization_pass import OptimizationPass
from .stack_canary_simplifier import StackCanarySimplifier
from .structured_optimization_pass import StructuredOptimizationPass

_all_optimization_passes = [
    StackCanarySimplifier,
    BasePointerSaveSimplifier,
    EmptyConditionalSimplifier
]

def _get_optimization_passes(arch, platform, optimization_ty=None):

    import archinfo

    if isinstance(arch, archinfo.Arch):
        arch = arch.name

    platform = platform.lower()

    passes = [ ]
    for pass_ in _all_optimization_passes:
        if (optimization_ty is None or issubclass(pass_, optimization_ty)) \
            and (pass_.ARCHES is None or arch in pass_.ARCHES) \
            and (pass_.PLATFORMS is None or platform in pass_.PLATFORMS):
            passes.append(pass_)

    return passes

def get_optimization_passes(arch, platform):
    return _get_optimization_passes(arch, platform)

def get_unstructured_optimization_passes(arch, platform):
    return _get_optimization_passes(arch, platform, OptimizationPass)

def get_structured_optimization_passes(arch, platform):
    return _get_optimization_passes(arch, platform, StructuredOptimizationPass)
