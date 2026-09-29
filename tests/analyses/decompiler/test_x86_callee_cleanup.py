#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

from angr.calling_conventions import SimCCMicrosoftCdecl, SimCCStdcall
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests", "i386", "windows")


class TestX86CalleeCleanup(unittest.TestCase):
    """
    Indirect call sites get a caller-cleanup prototype by default. When that leaves the caller's stack unbalanced, the
    decompiler uses the stack balance as evidence of callee cleanup.
    """

    @staticmethod
    def _decompile(binary: str, func_addr: int, call_insn_addr: int):
        proj, _ = load_project_with_scoped_cfg(os.path.join(test_location, binary), func_addr)
        func = proj.kb.functions[func_addr]
        dec = proj.analyses.Decompiler(func)
        assert dec.codegen is not None and dec.codegen.text is not None and dec.clinic is not None
        print_decompilation_result(dec)
        call_block = next(block for block in func.blocks if call_insn_addr in block.instruction_addrs)
        return proj, dec, call_block

    def test_indirect_stdcall_balances_the_stack(self):
        # sub_405553 calls RtlGetVersion through a pointer from GetProcAddress:
        #   push esi; call eax; neg eax; ...; pop edi; pop esi; ret
        proj, dec, call_block = self._decompile(
            "00f53f8bf3df545f0422a7c68170ac379ec8d78bee9782b49ce05b14f8bcc7d5", 0x405553, 0x40558C
        )
        assert type(proj.kb.callsite_prototypes.get_cc(call_block.addr)) is SimCCStdcall
        spt = dec.clinic._spt
        sp = proj.arch.sp_offset
        # the argument pushed before the call is popped by the callee
        assert spt.offset_before(call_block.addr, sp) == spt.offset_after(0x40558C, sp)
        assert spt.offset_before(0x405599, sp) == spt.offset_before(0x405553, sp)  # ret
        assert re.search(r"\bv\d+\(ptr\)", dec.codegen.text) is not None

    def test_unknown_direct_callee_cleanup_blocks_indirect_inference(self):
        # MSVC _local_unwind2: `push 0x101; call _NLG_Notify; call dword ptr [ebx + esi*4 + 8]`. _NLG_Notify pops the
        # argument (ret 4) but its prototype has no stack arguments, so the imbalance must not be attributed to the
        # indirect call.
        proj, _, call_block = self._decompile(
            "9f2ef84bde1e4ef445708cc5a605a09226363d502b1f5b5bf4a1cfc6dd5fc41e", 0x4029D2, 0x402A26
        )
        assert type(proj.kb.callsite_prototypes.get_cc(call_block.addr)) is SimCCMicrosoftCdecl

    def test_issue_7288_indirect_stdcall_with_split_off_helper_epilogue(self):
        # sub_4290e0 calls a runtime-resolved import with six stack arguments and never pops them. Its helper sub_423a40
        # has no ret of its own: the CFG split its epilogue (`add esp, 0x24; pop x4; ret`) off into sub_423b0f.
        binary = os.path.join(test_location, "82ce4d6615793fec42a57571f6161794de24362be69a5103cf3c1192aa4b6ecb")
        proj, _ = load_project_with_scoped_cfg(
            binary,
            0x4290E0,
            extra_func_addrs=[0x40C710, 0x40C720, 0x4402E0, 0x440350, 0x423A40, 0x423B0F, 0x423AEA, 0x423B00],
            expand_call_tree=False,
        )
        # jmp thunks to the allocator and to free, and the helper, are all caller-cleanup
        for addr in (0x40C710, 0x40C720, 0x423A40):
            assert type(proj.kb.functions[addr].calling_convention) is SimCCMicrosoftCdecl

        dec = proj.analyses.Decompiler(proj.kb.functions[0x4290E0], preset="malware")
        assert dec.codegen is not None and dec.clinic is not None
        print_decompilation_result(dec)
        for call_block_addr in (0x4291D2, 0x4292B4):
            cc = proj.kb.callsite_prototypes.get_cc(call_block_addr)
            proto = proj.kb.callsite_prototypes.get_prototype(call_block_addr)
            assert type(cc) is SimCCStdcall
            assert proto is not None and len(proto.args) == 6
        # the local frame stays put across both indirect calls
        spt = dec.clinic._spt
        sp = proj.arch.sp_offset
        frame = spt.offset_after(0x4290EC, sp)
        for addr in (0x4291E4, 0x429206, 0x4292BE):
            assert spt.offset_after(addr, sp) == frame


if __name__ == "__main__":
    unittest.main()
