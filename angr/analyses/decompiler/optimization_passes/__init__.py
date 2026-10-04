# pylint:disable=import-outside-toplevel
from __future__ import annotations

from typing import TYPE_CHECKING

from archinfo import Arch

from angr.analyses import decompiler

from .base_ptr_save_simplifier import BasePointerSaveSimplifier
from .call_stmt_rewriter import CallStatementRewriter
from .cmpf_value_lowering import CmpFValueLowering
from .code_motion import CodeMotionOptimization
from .condition_constprop import ConditionConstantPropagation
from .const_derefs import ConstantDereferencesSimplifier
from .const_prop_reverter import ConstPropOptReverter
from .cross_jump_reverter import CrossJumpReverter
from .deadblock_remover import DeadblockRemover
from .determine_load_sizes import DetermineLoadSizes
from .div_simplifier import DivSimplifier
from .duplication_reverter import DuplicationReverter
from .eager_std_string_concatenation import EagerStdStringConcatenationPass
from .eager_std_string_eval import EagerStdStringEvalPass
from .expr_op_swapper import ExprOpSwapper
from .flip_boolean_cmp import FlipBooleanCmp
from .float128_pair_coalescer import Float128PairCoalescer
from .fp_negation import FpNegation
from .inlined_memcpy_simplifier import InlinedMemcpySimplifier, InlinedMemcpySimplifierLate
from .inlined_memset_simplifier import InlinedMemsetSimplifier, InlinedMemsetSimplifierLate
from .inlined_strcpy_simplifier import InlinedStrcpySimplifier, InlinedStrcpySimplifierLate
from .inlined_string_transformation_simplifier import InlinedStringTransformationSimplifier
from .inlined_strlen_simplifier import InlinedStrlenSimplifier
from .inlined_wcscpy_simplifier import InlinedWcscpySimplifier, InlinedWcscpySimplifierLate
from .insert_extract_reverter import InsertExtractReverter
from .ireg_replacer import IRegReplacer
from .ite_expr_converter import ITEExprConverter
from .ite_region_converter import ITERegionConverter
from .ite_simplifier import ITESimplifier
from .known_pattern_outliner import KnownPatternOutliner
from .lowered_switch_simplifier import LoweredSwitchSimplifier
from .mips_gp_setting_simplifier import MipsGpSettingSimplifier
from .mod_simplifier import ModSimplifier
from .optimization_pass import OptimizationPassStage
from .pattern_outliner import PatternOutliner
from .peephole_simplifier import PostStructuringPeepholeOptimizationPass
from .register_save_area_simplifier import RegisterSaveAreaSimplifier
from .register_save_area_simplifier_adv import RegisterSaveAreaSimplifierAdvanced
from .ret_addr_save_simplifier import RetAddrSaveSimplifier
from .ret_deduplicator import ReturnDeduplicator
from .return_duplicator_high import ReturnDuplicatorHigh
from .return_duplicator_low import ReturnDuplicatorLow
from .stack_canary_simplifier import StackCanarySimplifier
from .static_vvar_rewriter import StaticVVarRewriter
from .switch_default_case_duplicator import SwitchDefaultCaseDuplicator
from .switch_reused_entry_rewriter import SwitchReusedEntryRewriter
from .tag_slicer import TagSlicer
from .win_stack_canary_simplifier import WinStackCanarySimplifier
from .x86_gcc_getpc_simplifier import X86GccGetPcSimplifier
from .x87_fprem_loop import X87FpremLoopSimplifier

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
    ITESimplifier,
    ConstantDereferencesSimplifier,
    RetAddrSaveSimplifier,
    X86GccGetPcSimplifier,
    MipsGpSettingSimplifier,
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
    # Simplify string transformation loops before other inlined string/memory operations use simplified output
    InlinedStringTransformationSimplifier,
    InlinedMemcpySimplifier,
    InlinedMemsetSimplifier,
    InlinedStrcpySimplifier,
    InlinedWcscpySimplifier,
    InlinedMemcpySimplifierLate,
    InlinedMemsetSimplifierLate,
    InlinedStrcpySimplifierLate,
    InlinedWcscpySimplifierLate,
    CallStatementRewriter,
    TagSlicer,
    ConditionConstantPropagation,
    DetermineLoadSizes,
    EagerStdStringConcatenationPass,
    PostStructuringPeepholeOptimizationPass,
    CmpFValueLowering,
    RegisterSaveAreaSimplifierAdvanced,
    InlinedStrlenSimplifier,
    X87FpremLoopSimplifier,
    FpNegation,
    Float128PairCoalescer,
    KnownPatternOutliner,
    PatternOutliner,
    StaticVVarRewriter,
    EagerStdStringEvalPass,
    IRegReplacer,
    InsertExtractReverter,
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
        for preset in presets:
            if isinstance(preset, str):
                preset = decompiler.presets.DECOMPILATION_PRESETS[
                    preset
                ]  # intentionally raise a KeyError if the preset is not found
            if opt_pass not in preset.opt_passes:
                preset.opt_passes.append(opt_pass)


__all__ = (
    "ALL_OPTIMIZATION_PASSES",
    "CONDENSING_OPTS",
    "DUPLICATING_OPTS",
    "BasePointerSaveSimplifier",
    "CallStatementRewriter",
    "CmpFValueLowering",
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
    "Float128PairCoalescer",
    "FpNegation",
    "IRegReplacer",
    "ITEExprConverter",
    "ITERegionConverter",
    "ITESimplifier",
    "InlinedMemcpySimplifier",
    "InlinedMemcpySimplifierLate",
    "InlinedMemsetSimplifier",
    "InlinedMemsetSimplifierLate",
    "InlinedStrcpySimplifier",
    "InlinedStrcpySimplifierLate",
    "InlinedStringTransformationSimplifier",
    "InlinedStrlenSimplifier",
    "InlinedWcscpySimplifier",
    "InlinedWcscpySimplifierLate",
    "InsertExtractReverter",
    "KnownPatternOutliner",
    "LoweredSwitchSimplifier",
    "MipsGpSettingSimplifier",
    "ModSimplifier",
    "OptimizationPassStage",
    "PatternOutliner",
    "RegisterSaveAreaSimplifier",
    "RegisterSaveAreaSimplifierAdvanced",
    "RetAddrSaveSimplifier",
    "ReturnDeduplicator",
    "ReturnDuplicatorHigh",
    "ReturnDuplicatorLow",
    "StackCanarySimplifier",
    "StaticVVarRewriter",
    "SwitchDefaultCaseDuplicator",
    "SwitchReusedEntryRewriter",
    "TagSlicer",
    "WinStackCanarySimplifier",
    "X86GccGetPcSimplifier",
    "X87FpremLoopSimplifier",
    "get_optimization_passes",
    "register_optimization_pass",
)
