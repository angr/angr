from __future__ import annotations
from .preset import DecompilationPreset
from angr.analyses.decompiler.optimization_passes import (
    RegisterSaveAreaSimplifier,
    StackCanarySimplifier,
    WinStackCanarySimplifier,
    BasePointerSaveSimplifier,
    DivSimplifier,
    MultiSimplifier,
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
    ConstPropOptReverter,
    DuplicationReverter,
    LoweredSwitchSimplifier,
    ReturnDuplicatorLow,
    ReturnDeduplicator,
    CrossJumpReverter,
    FlipBooleanCmp,
    InlinedStringTransformationSimplifier,
    CallStatementRewriter,
)


preset_full = DecompilationPreset(
    "full",
    [
        RegisterSaveAreaSimplifier,
        StackCanarySimplifier,
        WinStackCanarySimplifier,
        BasePointerSaveSimplifier,
        DivSimplifier,
        MultiSimplifier,
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
        ConstPropOptReverter,
        DuplicationReverter,
        LoweredSwitchSimplifier,
        ReturnDuplicatorLow,
        ReturnDeduplicator,
        CrossJumpReverter,
        FlipBooleanCmp,
        InlinedStringTransformationSimplifier,
        CallStatementRewriter,
    ],
)


__all__ = ["preset_full"]
