# pylint:disable=import-outside-toplevel
from typing import Optional, Union

from archinfo import Arch

from .optimization_pass import OptimizationPassStage
from .stack_canary_simplifier import StackCanarySimplifier
from .base_ptr_save_simplifier import BasePointerSaveSimplifier
from .multi_simplifier import MultiSimplifier
from .div_simplifier import DivSimplifier
from .mod_simplifier import ModSimplifier
from .eager_returns import EagerReturnsSimplifier
from .const_derefs import ConstantDereferencesSimplifier


_all_optimization_passes = [
    (StackCanarySimplifier, True),
    (BasePointerSaveSimplifier, True),
    (EagerReturnsSimplifier, True),
    (DivSimplifier, True),
    (MultiSimplifier, True),
    (ModSimplifier, True),
    (ConstantDereferencesSimplifier, True),
]

def get_optimization_passes(arch, platform):

    if isinstance(arch, Arch):
        arch = arch.name

    if platform is not None:
        platform = platform.lower()

    passes = [ ]
    for pass_, _ in _all_optimization_passes:
        if arch in pass_.ARCHES and (platform is None or platform in pass_.PLATFORMS):
            passes.append(pass_)

    return passes


def get_default_optimization_passes(arch: Union[Arch,str], platform: Optional[str]):

    if isinstance(arch, Arch):
        arch = arch.name

    if platform is not None:
        platform = platform.lower()

    passes = [ ]
    for pass_, default in _all_optimization_passes:
        if not default:
            continue
        if arch in pass_.ARCHES and (platform is None or platform in pass_.PLATFORMS):
            passes.append(pass_)

    return passes
