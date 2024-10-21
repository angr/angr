from __future__ import annotations
from .preset import DecompilationPreset
from angr.analyses.decompiler.optimization_passes import (
    RegisterSaveAreaSimplifier,
    StackCanarySimplifier,
    WinStackCanarySimplifier,
    BasePointerSaveSimplifier,
    ConstantDereferencesSimplifier,
    RetAddrSaveSimplifier,
    X86GccGetPcSimplifier,
    ITERegionConverter,
    ITEExprConverter,
    ExprOpSwapper,
    ReturnDuplicatorHigh,
    SwitchDefaultCaseDuplicator,
    LoweredSwitchSimplifier,
    ReturnDuplicatorLow,
    ReturnDeduplicator,
    FlipBooleanCmp,
    InlinedStringTransformationSimplifier,
    CallStatementRewriter,
    MultiSimplifier,
    DeadblockRemover,
)


preset_fast = DecompilationPreset(
    "fast",
    [
        RegisterSaveAreaSimplifier,
        StackCanarySimplifier,
        WinStackCanarySimplifier,
        BasePointerSaveSimplifier,
        MultiSimplifier,  # TODO: MultiSimplifier should be replaced by a peephole optimization
        ConstantDereferencesSimplifier,
        RetAddrSaveSimplifier,
        X86GccGetPcSimplifier,
        ITERegionConverter,
        ITEExprConverter,
        ExprOpSwapper,
        ReturnDuplicatorHigh,
        DeadblockRemover,
        SwitchDefaultCaseDuplicator,
        LoweredSwitchSimplifier,
        ReturnDuplicatorLow,
        ReturnDeduplicator,
        FlipBooleanCmp,
        InlinedStringTransformationSimplifier,
        CallStatementRewriter,
    ],
)


__all__ = ["preset_fast"]
