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
    CallStatementRewriter,
    SwitchReusedEntryRewriter,
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
        X86GccGetPcSimplifier,
        CallStatementRewriter,
        SwitchReusedEntryRewriter,
    ],
)


__all__ = ["preset_basic"]
