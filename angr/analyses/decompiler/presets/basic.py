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
    InlinedMemcpySimplifier,
    InlinedMemcpySimplifierLate,
    InlinedStrcpySimplifier,
    InlinedStrcpySimplifierLate,
    InlinedWcscpySimplifier,
    InlinedWcscpySimplifierLate,
    CallStatementRewriter,
    SwitchReusedEntryRewriter,
    PostStructuringPeepholeOptimizationPass,
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
        InlinedMemcpySimplifier,
        InlinedStrcpySimplifier,
        InlinedWcscpySimplifier,
        InlinedMemcpySimplifierLate,
        InlinedStrcpySimplifierLate,
        InlinedWcscpySimplifierLate,
        CallStatementRewriter,
        SwitchReusedEntryRewriter,
        PostStructuringPeepholeOptimizationPass,
    ],
)


__all__ = ["preset_basic"]
