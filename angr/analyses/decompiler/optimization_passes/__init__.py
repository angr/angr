# pylint:disable=import-outside-toplevel
from __future__ import annotations
from typing import TYPE_CHECKING

from archinfo import Arch

from .optimization_pass import OptimizationPassStage
from .stack_canary_simplifier import StackCanarySimplifier
from .base_ptr_save_simplifier import BasePointerSaveSimplifier
from .expr_op_swapper import ExprOpSwapper
from .ite_region_converter import ITERegionConverter
from .ite_expr_converter import ITEExprConverter
from .lowered_switch_simplifier import LoweredSwitchSimplifier
from .div_simplifier import DivSimplifier
from .mod_simplifier import ModSimplifier
from .return_duplicator_low import ReturnDuplicatorLow
from .return_duplicator_high import ReturnDuplicatorHigh
from .const_derefs import ConstantDereferencesSimplifier
from .register_save_area_simplifier import RegisterSaveAreaSimplifier
from .ret_addr_save_simplifier import RetAddrSaveSimplifier
from .x86_gcc_getpc_simplifier import X86GccGetPcSimplifier
from .flip_boolean_cmp import FlipBooleanCmp
from .ret_deduplicator import ReturnDeduplicator
from .win_stack_canary_simplifier import WinStackCanarySimplifier
from .cross_jump_reverter import CrossJumpReverter
from .code_motion import CodeMotionOptimization
from .switch_default_case_duplicator import SwitchDefaultCaseDuplicator
from .deadblock_remover import DeadblockRemover
from .tag_slicer import TagSlicer
from .inlined_string_transformation_simplifier import InlinedStringTransformationSimplifier
from .const_prop_reverter import ConstPropOptReverter
from .call_stmt_rewriter import CallStatementRewriter
from .duplication_reverter import DuplicationReverter
from .switch_reused_entry_rewriter import SwitchReusedEntryRewriter
from .condition_constprop import ConditionConstantPropagation
from .determine_load_sizes import DetermineLoadSizes
from .eager_std_string_concatenation import EagerStdStringConcatenationPass

if TYPE_CHECKING:
    from angr.analyses.decompiler.presets import DecompilationPreset


# order matters!
ALL_OPTIMIZATION_PASSES = [
    RegisterSaveAreaSimplifier,
    StackCanarySimplifier,
    WinStackCanarySimplifier,
    BasePointerSaveSimplifier,
    DivSimplifier,
    ModSimplifier,
    ConstantDereferencesSimplifier,
    RetAddrSaveSimplifier,
    X86GccGetPcSimplifier,
    ITERegionConverter,
    ITEExprConverter,
    ExprOpSwapper,
    ReturnDuplicatorHigh,
    DeadblockRemover,
    SwitchDefaultCaseDuplicator,
    SwitchReusedEntryRewriter,
    ConstPropOptReverter,
    DuplicationReverter,
    LoweredSwitchSimplifier,
    ReturnDuplicatorLow,
    ReturnDeduplicator,
    CodeMotionOptimization,
    CrossJumpReverter,
    FlipBooleanCmp,
    InlinedStringTransformationSimplifier,
    CallStatementRewriter,
    TagSlicer,
    ConditionConstantPropagation,
    DetermineLoadSizes,
    EagerStdStringConcatenationPass,
]

# these passes may duplicate code to remove gotos or improve the structure of the graph
DUPLICATING_OPTS = [ReturnDuplicatorLow, ReturnDuplicatorHigh, CrossJumpReverter]
# these passes may destroy blocks by merging them into semantically equivalent blocks
CONDENSING_OPTS = [CodeMotionOptimization, ReturnDeduplicator, DuplicationReverter]


def get_optimization_passes(arch, platform):
    if isinstance(arch, Arch):
        arch = arch.name

    if platform is not None:
        platform = platform.lower()
    if platform == "win32":
        platform = "windows"  # sigh

    passes = []
    for pass_ in ALL_OPTIMIZATION_PASSES:
        if (pass_.ARCHES is None or arch in pass_.ARCHES) and (
            pass_.PLATFORMS is None or platform is None or platform in pass_.PLATFORMS
        ):
            passes.append(pass_)

    return passes


def register_optimization_pass(opt_pass, *, presets: list[str | DecompilationPreset] | None = None):
    ALL_OPTIMIZATION_PASSES.append(opt_pass)

    if presets:
        from angr.analyses.decompiler.presets import DECOMPILATION_PRESETS

        for preset in presets:
            if isinstance(preset, str):
                preset = DECOMPILATION_PRESETS[preset]  # intentionally raise a KeyError if the preset is not found
            if opt_pass not in preset.opt_passes:
                preset.opt_passes.append(opt_pass)


__all__ = (
    "ALL_OPTIMIZATION_PASSES",
    "CONDENSING_OPTS",
    "DUPLICATING_OPTS",
    "BasePointerSaveSimplifier",
    "CallStatementRewriter",
    "CodeMotionOptimization",
    "ConditionConstantPropagation",
    "ConstPropOptReverter",
    "ConstantDereferencesSimplifier",
    "CrossJumpReverter",
    "DeadblockRemover",
    "DivSimplifier",
    "DuplicationReverter",
    "EagerStdStringConcatenationPass",
    "ExprOpSwapper",
    "FlipBooleanCmp",
    "ITEExprConverter",
    "ITERegionConverter",
    "InlinedStringTransformationSimplifier",
    "LoweredSwitchSimplifier",
    "ModSimplifier",
    "OptimizationPassStage",
    "RegisterSaveAreaSimplifier",
    "RetAddrSaveSimplifier",
    "ReturnDeduplicator",
    "ReturnDuplicatorHigh",
    "ReturnDuplicatorLow",
    "StackCanarySimplifier",
    "SwitchDefaultCaseDuplicator",
    "SwitchReusedEntryRewriter",
    "TagSlicer",
    "WinStackCanarySimplifier",
    "X86GccGetPcSimplifier",
    "get_optimization_passes",
    "register_optimization_pass",
)
