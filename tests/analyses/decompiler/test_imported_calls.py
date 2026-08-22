from __future__ import annotations

import struct

import angr
from angr.sim_type import SimStruct, SimTypeFunction, SimTypePointer


def _decompile_shellcode_call(caller: bytes, callee):
    base = 0x400000
    code = caller + b"\x90" * (0x20 - len(caller)) + b"\xc3"
    project = angr.load_shellcode(code, arch="amd64", load_address=base)
    callee(project, base + 0x20)
    cfg = project.analyses.CFGFast(
        function_starts=[base, base + 0x20],
        normalize=True,
        data_references=True,
    )
    dec = project.analyses.Decompiler(
        cfg.functions.function(addr=base),
        cfg=cfg.model,
        fail_fast=True,
    )
    assert dec.codegen is not None
    return dec.codegen.text


def test_known_void_call_does_not_define_return_register():
    caller = bytes.fromhex(
        "55 "  # push rbp
        "48 89 e5 "  # mov rbp, rsp
        "b8 07 00 00 00 "  # mov eax, 7
        "31 ff "  # xor edi, edi
        "e8 10 00 00 00 "  # call 0x400020
        "48 89 c3 "  # mov rbx, rax
        "48 89 d8 "  # mov rax, rbx
        "c9 "  # leave
        "c3"  # ret
    )

    def define_srand(project, address):
        cfg = project.analyses.CFGFast(
            function_starts=[address],
            normalize=True,
            data_references=True,
        )
        callee = cfg.functions.function(addr=address)
        callee.name = "srand"
        callee.apply_definition("void srand(unsigned int seed)")

    text = _decompile_shellcode_call(caller, define_srand)

    assert "srand(0);" in text
    assert "= srand(" not in text
    assert "return (unsigned long long)srand(" not in text


def test_export_alias_uses_public_declaration_name():
    caller = bytes.fromhex(
        "55 "  # push rbp
        "48 89 e5 "  # mov rbp, rsp
        "be 00 00 00 00 "  # mov esi, 0
        "bf 02 00 00 00 "  # mov edi, 2
        "e8 0d 00 00 00 "  # call 0x400020
        "31 c0 "  # xor eax, eax
        "c9 "  # leave
        "c3"  # ret
    )

    def hook_signal(project, address):
        libc = angr.SIM_LIBRARIES["libc.so.6"][0]
        project.hook(address, libc.get_stub("__sysv_signal", project.arch))

    text = _decompile_shellcode_call(caller, hook_signal)

    assert "signal(2, NULL);" in text
    assert "__sysv_signal" not in text


def test_glibc_callback_and_termios_prototypes_keep_structural_abi_types():
    libc = angr.SIM_LIBRARIES["libc.so.6"][0]
    arch = angr.load_shellcode(b"\xc3", arch="amd64").arch

    signal = libc.get_prototype("signal", arch=arch, deref=True)
    assert signal is not None
    assert isinstance(signal.returnty, SimTypePointer)
    assert isinstance(signal.returnty.pts_to, SimTypeFunction)
    assert isinstance(signal.args[1], SimTypePointer)
    assert isinstance(signal.args[1].pts_to, SimTypeFunction)

    tcgetattr = libc.get_prototype("tcgetattr", arch=arch, deref=True)
    assert tcgetattr is not None
    assert isinstance(tcgetattr.args[1], SimTypePointer)
    termios = tcgetattr.args[1].pts_to.with_arch(arch)
    assert isinstance(termios, SimStruct)
    assert termios.offsets["c_oflag"] == 4
    assert termios.offsets["c_cflag"] == 8
    assert termios.offsets["c_lflag"] == 12


def test_printf_dynamic_width_arguments_are_recovered():
    base = 0x400000
    printf_addr = base + 0x80
    format_addr = base + 0x100
    empty_string_addr = format_addr + len(b"%*s%u%*s\x00")

    code = bytearray(
        bytes.fromhex(
            "55 "  # push rbp
            "48 89 e5 "  # mov rbp, rsp
            "be 03 00 00 00 "  # mov esi, 3
        )
    )

    def append_rip_relative_lea(opcode: bytes, target: int):
        instruction_addr = base + len(code)
        code.extend(opcode)
        code.extend(struct.pack("<i", target - (instruction_addr + len(opcode) + 4)))

    append_rip_relative_lea(bytes.fromhex("48 8d 3d"), format_addr)  # lea rdi, [rip + format]
    append_rip_relative_lea(bytes.fromhex("48 8d 15"), empty_string_addr)  # lea rdx, [rip + empty]
    code.extend(bytes.fromhex("b9 2a 00 00 00"))  # mov ecx, 42
    code.extend(bytes.fromhex("41 b8 04 00 00 00"))  # mov r8d, 4
    append_rip_relative_lea(bytes.fromhex("4c 8d 0d"), empty_string_addr)  # lea r9, [rip + empty]
    call_addr = base + len(code)
    code.extend(b"\xe8" + struct.pack("<i", printf_addr - (call_addr + 5)))
    code.extend(bytes.fromhex("31 c0 c9 c3"))  # xor eax, eax; leave; ret
    code.extend(b"\x90" * (printf_addr - base - len(code)))
    code.extend(b"\xc3")
    code.extend(b"\x90" * (format_addr - base - len(code)))
    code.extend(b"%*s%u%*s\x00\x00")

    project = angr.load_shellcode(bytes(code), arch="amd64", load_address=base)
    format_segment = project.loader.find_segment_containing(format_addr)
    assert format_segment is not None and format_segment.is_writable
    libc = angr.SIM_LIBRARIES["libc.so.6"][0]
    project.hook(printf_addr, libc.get("printf", project.arch))
    cfg = project.analyses.CFGFast(
        function_starts=[base, printf_addr],
        normalize=True,
        data_references=True,
    )
    dec = project.analyses.Decompiler(
        cfg.functions.function(addr=base),
        cfg=cfg.model,
        fail_fast=True,
    )

    assert dec.codegen is not None
    text = dec.codegen.text
    call = next(line.strip() for line in text.splitlines() if line.strip().startswith("printf("))
    arguments = call.removeprefix("printf(").removesuffix(");").split(", ")
    assert len(arguments) == 6
    assert arguments[0] == "(char *)0x400100"
    assert arguments[1] == "3"
    assert arguments[2].endswith("&g_400109")
    assert arguments[3:5] == ["42", "4"]
    assert arguments[5].endswith("&g_400109")
