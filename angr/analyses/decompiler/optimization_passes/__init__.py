# pylint:disable=import-outside-toplevel
from typing import Optional, Union

from archinfo import Arch

from .optimization_pass import OptimizationPassStage
from .stack_canary_simplifier import StackCanarySimplifier
from .base_ptr_save_simplifier import BasePointerSaveSimplifier
from .expr_op_swapper import ExprOpSwapper
from .ite_region_converter import ITERegionConverter
from .ite_expr_converter import ITEExprConverter
from .lowered_switch_simplifier import LoweredSwitchSimplifier
from .multi_simplifier import MultiSimplifier
from .div_simplifier import DivSimplifier
from .mod_simplifier import ModSimplifier
from .eager_returns import EagerReturnsSimplifier
from .const_derefs import ConstantDereferencesSimplifier
from .register_save_area_simplifier import RegisterSaveAreaSimplifier
from .ret_addr_save_simplifier import RetAddrSaveSimplifier
from .x86_gcc_getpc_simplifier import X86GccGetPcSimplifier
from .flip_boolean_cmp import FlipBooleanCmp
from .ret_deduplicator import ReturnDeduplicator
from .win_stack_canary_simplifier import WinStackCanarySimplifier


_all_optimization_passes = [
    (RegisterSaveAreaSimplifier, True),
    (StackCanarySimplifier, True),
    (WinStackCanarySimplifier, True),
    (BasePointerSaveSimplifier, True),
    (DivSimplifier, True),
    (MultiSimplifier, True),
    (ModSimplifier, True),
    (ConstantDereferencesSimplifier, True),
    (RetAddrSaveSimplifier, True),
    (X86GccGetPcSimplifier, True),
    (ITERegionConverter, True),
    (ReturnDeduplicator, True),
    (LoweredSwitchSimplifier, False),
    (EagerReturnsSimplifier, True),
    (ITEExprConverter, True),
    (ExprOpSwapper, True),
    (FlipBooleanCmp, True),
]


def get_optimization_passes(arch, platform):
    if isinstance(arch, Arch):
        arch = arch.name

    if platform is not None:
        platform = platform.lower()

    passes = []
    for pass_, _ in _all_optimization_passes:
        if (pass_.ARCHES is None or arch in pass_.ARCHES) and (
            pass_.PLATFORMS is None or platform is None or platform in pass_.PLATFORMS
        ):
            passes.append(pass_)

    return passes


def get_default_optimization_passes(arch: Union[Arch, str], platform: Optional[str]):
    if isinstance(arch, Arch):
        arch = arch.name

    if platform is not None:
        platform = platform.lower()
    if platform == "win32":
        platform = "windows"  # sigh

    passes = []
    for pass_, default in _all_optimization_passes:
        if not default:
            continue
        if (pass_.ARCHES is None or arch in pass_.ARCHES) and (
            pass_.PLATFORMS is None or platform is None or platform in pass_.PLATFORMS
        ):
            passes.append(pass_)

    return passes
