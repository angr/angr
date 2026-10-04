from __future__ import annotations

from angr.analyses.decompiler.optimization_passes import (
    BasePointerSaveSimplifier,
    CallStatementRewriter,
    CmpFValueLowering,
    ConstantDereferencesSimplifier,
    Float128PairCoalescer,
    FpNegation,
    InlinedMemcpySimplifier,
    InlinedMemcpySimplifierLate,
    InlinedMemsetSimplifier,
    InlinedMemsetSimplifierLate,
    InlinedStrcpySimplifier,
    InlinedStrcpySimplifierLate,
    InlinedWcscpySimplifier,
    InlinedWcscpySimplifierLate,
    InsertExtractReverter,
    IRegReplacer,
    MipsGpSettingSimplifier,
    PostStructuringPeepholeOptimizationPass,
    RegisterSaveAreaSimplifier,
    RegisterSaveAreaSimplifierAdvanced,
    RetAddrSaveSimplifier,
    StackCanarySimplifier,
    SwitchReusedEntryRewriter,
    WinStackCanarySimplifier,
    X86GccGetPcSimplifier,
)

from .preset import DecompilationPreset

preset_basic = DecompilationPreset(
    "basic",
    [
        RegisterSaveAreaSimplifier,
        StackCanarySimplifier,
        WinStackCanarySimplifier,
        BasePointerSaveSimplifier,
        ConstantDereferencesSimplifier,
        RetAddrSaveSimplifier,
        RegisterSaveAreaSimplifierAdvanced,
        X86GccGetPcSimplifier,
        MipsGpSettingSimplifier,
        InlinedMemcpySimplifier,
        InlinedMemsetSimplifier,
        InlinedStrcpySimplifier,
        InlinedWcscpySimplifier,
        InlinedMemcpySimplifierLate,
        InlinedMemsetSimplifierLate,
        InlinedStrcpySimplifierLate,
        InlinedWcscpySimplifierLate,
        CallStatementRewriter,
        SwitchReusedEntryRewriter,
        PostStructuringPeepholeOptimizationPass,
        CmpFValueLowering,
        IRegReplacer,
        InsertExtractReverter,
        FpNegation,
        Float128PairCoalescer,
    ],
)


__all__ = ["preset_basic"]
