#!/usr/bin/env python3
# pylint: disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import struct
import unittest

import archinfo

import angr

BASE = 0x400000
CALLBACK = object()  # stands in for the address of the callback, which is only known after layout


def _segment_override_caller(args):
    """
    Build an x86 function that reads through %gs and then calls an imported function with ``args``,
    and return the blob together with the addresses CFGFast will see.

    A segment override lifts to an ``Ijk_MapFail`` exit guarded on the selector translation failing,
    so the first block has a failure successor that the engine cannot step. That block is the
    predecessor CFGFast hands to the callee's ``static_exits`` or ``dynamic_returns``.
    """

    code = bytearray()
    code += b"\xbc\x00\x00\x41\x00"  # mov esp, 0x410000
    code += b"\x65\xa1\x00\x00\x00\x00"  # mov eax, gs:[0]
    code += b"\xeb\x00"  # jmp +0, ending the block
    arg_operands = []
    for arg in reversed(args):
        code += b"\x68\x00\x00\x00\x00"  # push arg (patched below)
        arg_operands.append((len(code) - 4, arg))
    code += b"\xe8\x00\x00\x00\x00"  # call import (patched below)
    call_operand = len(code) - 4
    return_site = len(code)
    code += bytes((0x83, 0xC4, 4 * len(args)))  # add esp, 4 * len(args)
    code += b"\xc3"  # ret
    callback = len(code)
    code += b"\x31\xc0\xc3"  # xor eax, eax; ret
    import_stub = len(code)
    code += b"\xc3"  # ret, replaced by the hook

    for operand, arg in arg_operands:
        struct.pack_into("<I", code, operand, BASE + callback if arg is CALLBACK else arg)
    struct.pack_into("<i", code, call_operand, import_stub - return_site)
    return bytes(code), BASE + return_site, BASE + callback, BASE + import_stub


def _cfg_calling(procedure_name, args):
    """
    Recover a CFG of a caller that passes ``args`` to ``procedure_name`` over a segment override.
    """

    code, return_site, callback, import_stub = _segment_override_caller(args)
    arch = archinfo.arch_from_id("x86")
    proj = angr.load_shellcode(code, arch, load_address=BASE)
    proj.hook(import_stub, angr.SIM_LIBRARIES["libc.so.6"][0].get(procedure_name, arch))
    return proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True), return_site, callback


class TestCfgSimProcedureExits(unittest.TestCase):
    """
    CFGFast asks a hooked SimProcedure to pre-execute the blocks leading up to a call site. Those
    blocks can produce failure successors, and stepping one raises AngrExitError out of the whole
    analysis unless the procedure keeps to successors that execution can continue from.
    """

    def test_pthread_create_static_exits_over_segment_override(self):
        # pthread_create(thread, attr, start_routine, arg)
        cfg, _, callback = _cfg_calling("pthread_create", (0, 0, CALLBACK, 0))

        # static_exits recovered the thread entry point from the call site
        assert callback in cfg.functions
        assert cfg.kb.labels[callback] == "thread_entry"

    def test_libc_start_main_static_exits_over_segment_override(self):
        # __libc_start_main(main, argc, argv, init, fini)
        cfg, _, callback = _cfg_calling("__libc_start_main", (CALLBACK, 1, 0, 0, 0))

        # static_exits recovered main from the call site
        assert callback in cfg.functions
        assert cfg.kb.labels[callback] == "main"

    def test_error_dynamic_returns_over_segment_override(self):
        # error(status, errnum, fmt) does not return when status is nonzero
        cfg, return_site, _ = _cfg_calling("error", (1, 0, 0))

        # dynamic_returns read the nonzero status off the stack, so the call site does not return
        caller = cfg.functions.get_by_addr(BASE)
        assert caller.returning is False
        assert return_site not in {block.addr for block in caller.blocks}


if __name__ == "__main__":
    unittest.main()
