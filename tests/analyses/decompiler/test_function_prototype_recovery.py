from __future__ import annotations

import struct

import angr
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypePointer


def test_full_width_argument_keeps_abi_width_after_type_recovery():
    base = 0x400000
    callee_addr = base + 0x60
    passthrough_addr = base + 0x80
    caller_addr = base + 0xA0

    pointer_user_prefix = bytes.fromhex(
        "55 "  # push rbp
        "48 89 e5 "  # mov rbp, rsp
        "48 83 ec 20 "  # sub rsp, 0x20
        "48 89 7d e8 "  # mov [rbp-0x18], rdi
        "c6 45 ff 01 "  # mov byte ptr [rbp-1], 1
        "0f b6 45 ff "  # movzx eax, byte ptr [rbp-1]
        "48 8d 14 85 00 00 00 00 "  # lea rdx, [rax*4]
        "48 8b 45 e8 "  # mov rax, [rbp-0x18]
        "48 01 c2 "  # add rdx, rax
        "c6 02 00 "  # mov byte ptr [rdx], 0
        "48 8b 45 e8 "  # mov rax, [rbp-0x18]
        "48 89 c7"  # mov rdi, rax
    )
    pointer_user = (
        pointer_user_prefix
        + b"\xe8"
        + struct.pack("<i", callee_addr - (base + len(pointer_user_prefix) + 5))
        + bytes.fromhex("c9 c3")  # leave; ret
    )
    passthrough_prefix = bytes.fromhex(
        "55 "  # push rbp
        "48 89 e5 "  # mov rbp, rsp
        "48 83 ec 10 "  # sub rsp, 0x10
        "48 89 7d f8 "  # mov [rbp-8], rdi
        "48 8b 45 f8 "  # mov rax, [rbp-8]
        "48 89 c7"  # mov rdi, rax
    )
    passthrough = (
        passthrough_prefix
        + b"\xe8"
        + struct.pack("<i", base - (passthrough_addr + len(passthrough_prefix) + 5))
        + bytes.fromhex("c9 c3")  # leave; ret
    )
    caller_prefix = bytes.fromhex(
        "55 "  # push rbp
        "48 89 e5 "  # mov rbp, rsp
        "48 83 ec 10 "  # sub rsp, 0x10
        "48 8d 45 ff "  # lea rax, [rbp-1]
        "48 89 c7"  # mov rdi, rax
    )
    caller = (
        caller_prefix
        + b"\xe8"
        + struct.pack("<i", passthrough_addr - (caller_addr + len(caller_prefix) + 5))
        + bytes.fromhex("c9 c3")  # leave; ret
    )
    code = (
        pointer_user
        + b"\x90" * (callee_addr - base - len(pointer_user))
        + bytes.fromhex("b8 01 00 00 00 c3")
        + b"\x90" * (passthrough_addr - callee_addr - 6)
        + passthrough
        + b"\x90" * (caller_addr - passthrough_addr - len(passthrough))
        + caller
    )

    project = angr.load_shellcode(code, arch="amd64", load_address=base)
    cfg = project.analyses.CFGFast(
        function_starts=[base, callee_addr, passthrough_addr, caller_addr],
        normalize=True,
        data_references=True,
    )
    pointer_user_func = cfg.functions.function(addr=base)
    callee_func = cfg.functions.function(addr=callee_addr)
    passthrough_func = cfg.functions.function(addr=passthrough_addr)
    caller_func = cfg.functions.function(addr=caller_addr)

    pointer_user_func.calling_convention = angr.calling_conventions.SimCCSystemVAMD64(project.arch)
    pointer_user_func.prototype = SimTypeFunction([SimTypeLongLong()], SimTypeBottom(label="void")).with_arch(
        project.arch
    )
    pointer_user_func.prototype_source = PrototypeSource.CCA_LOW
    callee_func.calling_convention = angr.calling_conventions.SimCCSystemVAMD64(project.arch)
    callee_func.prototype = SimTypeFunction([SimTypeLong(signed=False)], SimTypeInt()).with_arch(project.arch)
    callee_func.prototype_source = PrototypeSource.CCA_DECOMPILER
    passthrough_func.calling_convention = angr.calling_conventions.SimCCSystemVAMD64(project.arch)
    passthrough_func.prototype = SimTypeFunction([SimTypeLongLong()], SimTypeBottom(label="void")).with_arch(
        project.arch
    )
    passthrough_func.prototype_source = PrototypeSource.CCA_LOW

    pointer_user_decompilation = project.analyses.Decompiler(
        pointer_user_func,
        cfg=cfg.model,
        fail_fast=True,
    )
    passthrough_decompilation = project.analyses.Decompiler(
        passthrough_func,
        cfg=cfg.model,
        fail_fast=True,
    )
    caller_decompilation = project.analyses.Decompiler(
        caller_func,
        cfg=cfg.model,
        fail_fast=True,
    )

    assert pointer_user_decompilation.codegen is not None
    assert passthrough_decompilation.codegen is not None
    assert caller_decompilation.codegen is not None
    assert isinstance(pointer_user_func.prototype.args[0], SimTypePointer)
    assert isinstance(passthrough_func.prototype.args[0], SimTypePointer)
    assert "unsigned char *a0" in pointer_user_decompilation.codegen.text
    assert "unsigned char *a0" in passthrough_decompilation.codegen.text
    assert "sub_400080(&v0);" in caller_decompilation.codegen.text


def test_authoritative_narrow_argument_handles_full_register_read():
    project = angr.load_shellcode(bytes.fromhex("48 89 f8 c3"), arch="amd64", load_address=0x400000)
    cfg = project.analyses.CFGFast(function_starts=[0x400000], normalize=True)
    function = cfg.functions[0x400000]
    function.calling_convention = angr.calling_conventions.SimCCSystemVAMD64(project.arch)
    user_prototype = SimTypeFunction([SimTypeInt()], SimTypeInt()).with_arch(project.arch)
    function.prototype = user_prototype
    function.prototype_source = PrototypeSource.USER

    decompilation = project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=True,
        use_cache=False,
        update_cache=False,
    )

    assert decompilation.codegen is not None
    assert decompilation.codegen.text is not None
    assert function.prototype == user_prototype
    assert function.prototype_source is PrototypeSource.USER
    assert "int sub_400000(int a0)" in decompilation.codegen.text
