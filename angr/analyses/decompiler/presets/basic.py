from __future__ import annotations
from .preset import DecompilationPreset
from angr.analyses.decompiler.optimization_passes import (
    RegisterSaveAreaSimplifier,
    StackCanarySimplifier,
    WinStackCanarySimplifier,
    BasePointerSaveSimplifier,
    ConstantDereferencesSimplifier,
    RetAddrSaveSimplifier,
    RegisterSaveAreaSimplifierAdvanced,
    X86GccGetPcSimplifier,
    MipsGpSettingSimplifier,
    CallStatementRewriter,
    SwitchReusedEntryRewriter,
    PostStructuringPeepholeOptimizationPass,
    IRegReplacer,
    InsertExtractReverter,
)

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
        CallStatementRewriter,
        SwitchReusedEntryRewriter,
        PostStructuringPeepholeOptimizationPass,
        IRegReplacer,
        InsertExtractReverter,
    ],
)


__all__ = ["preset_basic"]
