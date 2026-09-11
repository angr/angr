#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures.posix"  # pylint:disable=redefined-builtin

import unittest

import archinfo

import angr

BASE_ADDR = 0x400000


def assemble(arch: archinfo.Arch, code: str, addr: int = BASE_ADDR) -> bytes:
    encoded = arch.asm(code, addr)
    assert isinstance(encoded, bytes)
    return encoded


def call_site(arch: archinfo.Arch, thread_entry: int, callee: int = BASE_ADDR) -> bytes:
    """
    Assemble a call to pthread_create passing ``thread_entry`` as its start_routine argument.
    """
    return assemble(
        arch,
        f"mov rdx, {thread_entry:#x}\nxor rcx, rcx\nxor rsi, rsi\nxor rdi, rdi\ncall {callee:#x}\nret\n",
    )


class TestPthreadCreateStaticExits(unittest.TestCase):
    """
    CFGFast calls pthread_create.static_exits() to recover the entry point of the spawned thread.
    """

    def test_static_exits_uses_the_blocks_it_is_given(self):
        # hand static_exits() a block lifted from different bytes than memory holds, and see which start_routine
        # comes back out
        arch = archinfo.arch_from_id("AMD64")
        proj = angr.load_shellcode(call_site(arch, 0x400800), arch=arch, load_address=BASE_ADDR)
        block = proj.factory.block(BASE_ADDR, byte_string=call_site(arch, 0x400900)).vex

        procedure = angr.SIM_PROCEDURES["posix"]["pthread_create"](
            project=proj, cc=angr.calling_conventions.SimCCSystemVAMD64(arch)
        )
        exits = procedure.static_exits([block])

        thread_exit = next(exit_ for exit_ in exits if exit_["jumpkind"] == "Ijk_Call")
        assert thread_exit["address"].concrete_value == 0x400900

    def test_static_exits_falls_back_to_the_default_calling_convention(self):
        arch = archinfo.arch_from_id("AMD64")
        proj = angr.load_shellcode(call_site(arch, 0x400800), arch=arch, load_address=BASE_ADDR)

        procedure = angr.SIM_PROCEDURES["posix"]["pthread_create"](project=proj)
        assert procedure.cc is None
        exits = procedure.static_exits([proj.factory.block(BASE_ADDR).vex])

        thread_exit = next(exit_ for exit_ in exits if exit_["jumpkind"] == "Ijk_Call")
        assert thread_exit["address"].concrete_value == 0x400800

    def test_pcode_cfg_recovers_the_thread_entry(self):
        amd64 = archinfo.arch_from_id("AMD64")
        # assemble once against a placeholder to measure the call site, then again with the real addresses
        placeholder = call_site(amd64, BASE_ADDR)
        hook_addr = BASE_ADDR + len(placeholder)
        thread_entry = hook_addr + 1
        code = call_site(amd64, thread_entry, hook_addr)
        assert len(code) == len(placeholder)
        code += assemble(amd64, "ret\n", hook_addr)
        code += assemble(amd64, "xor rax, rax\nret\n", thread_entry)

        arch = archinfo.ArchPcode("x86:LE:64:default")
        proj = angr.load_shellcode(
            code,
            arch=arch,
            load_address=BASE_ADDR,
            start_offset=BASE_ADDR,
            engine=angr.engines.UberEnginePcode,
        )
        proj.hook(hook_addr, angr.SIM_PROCEDURES["posix"]["pthread_create"]())

        # the thread entry is unreachable by scanning, so only static_exits() can find it
        cfg = proj.analyses.CFGFast(force_smart_scan=False, force_complete_scan=False)
        assert cfg.kb.labels.get(thread_entry) == "thread_entry"
        assert thread_entry in cfg.functions


if __name__ == "__main__":
    unittest.main()
