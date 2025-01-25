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
    DeadblockRemover,
    SwitchReusedEntryRewriter,
    ConditionConstantPropagation,
)


preset_fast = DecompilationPreset(
    "fast",
    [
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
        DeadblockRemover,
        SwitchDefaultCaseDuplicator,
        SwitchReusedEntryRewriter,
        LoweredSwitchSimplifier,
        ReturnDuplicatorLow,
        ReturnDeduplicator,
        FlipBooleanCmp,
        InlinedStringTransformationSimplifier,
        CallStatementRewriter,
        ConditionConstantPropagation,
    ],
)


__all__ = ["preset_fast"]
