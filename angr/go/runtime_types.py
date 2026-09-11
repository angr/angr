from __future__ import annotations

from angr.sim_type import SimStruct, SimTypeLength, SimTypePointer

# the register that holds the current goroutine (g) under Go's register ABI
G_REGISTERS = {
    "AMD64": "r14",
    "AARCH64": "x28",
}

# the register a closure body receives its closure record (context) pointer in
CONTEXT_REGISTERS = {
    "AMD64": "rdx",
    "AARCH64": "x26",
    "X86": "edx",
}


def go_g_struct(arch) -> SimStruct:
    """
    The leading fields of runtime.g. Only the version-stable prefix is described.
    """
    uintptr = SimTypeLength()
    return SimStruct(
        {
            "stack_lo": uintptr,
            "stack_hi": uintptr,
            "stackguard0": uintptr,
            "stackguard1": uintptr,
            "_panic": SimTypePointer(SimStruct({}, name="runtime._panic")),
            "_defer": SimTypePointer(SimStruct({}, name="runtime._defer")),
            "m": SimTypePointer(SimStruct({}, name="runtime.m")),
        },
        name="runtime.g",
    ).with_arch(arch)
