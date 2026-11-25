# pylint:disable=missing-class-docstring,missing-function-docstring,no-self-use
"""
Tests for tail-call targets being recovered as separate functions.

``tailcall_dispatch_*`` are stripped PIE builds of tests_src/tailcall_dispatch.c: ``key_verify`` dispatches through a
jump table whose cases are ``jmp verify_x`` tail calls, and ``verify_a``..``verify_f`` are reached only through those
jumps. Without a boundary at each target, CFGFast absorbs all of them into ``key_verify``.

- ``tailcall_dispatch_nocet``: .eh_frame FDEs, no endbr64. Only the FDE boundaries split the targets.
- ``tailcall_dispatch_cet_nofde``: endbr64, no FDEs for the functions. Only the endbr64 heuristic splits them.
- ``tailcall_dispatch_cet``: both.

``tailcall_table_dispatch`` is a stripped PIE build of tests_src/tailcall_table_dispatch.c: eight handlers are reached
only through a table of function pointers, and ``decode`` and every handler end in an indirect jump through that table.
``computed_goto_label_table`` and ``computed_goto_stateless_labels`` are computed gotos whose label tables are encoded
like tables of function pointers.
"""

from __future__ import annotations

import io
import os
import unittest

import angr
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests", "x86_64")

# nocet has a different layout after verify_c
CET_TARGETS = {0x4011C0, 0x401250, 0x4012E0, 0x401390, 0x401420, 0x4014B0}
NOCET_TARGETS = {0x4011C0, 0x401250, 0x4012E0, 0x401380, 0x401410, 0x4014A0}
KEY_VERIFY_COLD = 0x401050
CET_KEY_VERIFY = 0x401540
NOCET_KEY_VERIFY = 0x401530
# op_done, op_seg, op_bad, op_vex, op_lock, op_rep, op_size, op_rex
TABLE_HANDLERS = {0x401170, 0x401180, 0x4011D0, 0x4011E0, 0x401210, 0x401250, 0x401290, 0x4012D0}
TABLE_DECODE = 0x401320
# op_halt, op_inc, op_dec, op_dbl, op_neg: labels of run(), aligned to 16 bytes like function entries
COMPUTED_GOTO_LABELS = {0x401160, 0x401190, 0x4011A0, 0x4011B0, 0x4011C0}
# op1, op0: labels of dispatch() that only set the return value and return
STATELESS_LABELS = {0x401150, 0x401160}


class TestCfgFastEhFrameBoundaries(unittest.TestCase):
    def _cfg(self, binary: str, **kwargs):
        proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
        return proj.analyses.CFGFast(normalize=True, **kwargs)

    def test_fde_boundaries_split_tail_calls(self):
        cfg = self._cfg("tailcall_dispatch_nocet")
        assert set(cfg.kb.functions).issuperset(NOCET_TARGETS)
        key_verify = cfg.kb.functions[NOCET_KEY_VERIFY]
        assert not key_verify.block_addrs_set & NOCET_TARGETS
        assert all(cfg.kb.functions[addr].returning for addr in NOCET_TARGETS)

    def test_fde_boundaries_can_be_disabled(self):
        cfg = self._cfg("tailcall_dispatch_nocet", eh_frame_boundaries=False)
        # nothing else identifies these functions, so the tail-called targets are absorbed
        assert not NOCET_TARGETS & set(cfg.kb.functions)

    def test_endbr_targets_split_without_fdes(self):
        cfg = self._cfg("tailcall_dispatch_cet_nofde")
        assert set(cfg.kb.functions).issuperset(CET_TARGETS)
        assert not cfg.kb.functions[CET_KEY_VERIFY].block_addrs_set & CET_TARGETS

    def test_endbr_targets_split_with_boundaries_disabled(self):
        cfg = self._cfg("tailcall_dispatch_cet", eh_frame_boundaries=False)
        assert set(cfg.kb.functions).issuperset(CET_TARGETS)

    def test_cold_part_stays_with_its_function(self):
        # key_verify.cold has its own FDE but is only reached by a conditional jump from key_verify
        for binary, key_verify in (
            ("tailcall_dispatch_cet", CET_KEY_VERIFY),
            ("tailcall_dispatch_nocet", NOCET_KEY_VERIFY),
        ):
            cfg = self._cfg(binary)
            assert KEY_VERIFY_COLD not in cfg.kb.functions
            assert KEY_VERIFY_COLD in cfg.kb.functions[key_verify].block_addrs_set

    def test_noreturn_tail_called_function_with_endbr_is_not_a_cold_chunk(self):
        # sftp-server: main ends with `jmp sftp_server_main`, which never returns and is reached by nothing else.
        # Its FDE start used to be dropped as a cold chunk of main; the endbr64 at the target says it is a function.
        main, sftp_server_main = 0x405180, 0x40DD00
        _, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "decompiler", "sftp-server_O2_noinline_stripped"),
            main,
            extra_func_addrs=[sftp_server_main],
            window=0x900,
            expand_call_tree=False,
            run_ccc=False,
            cfg_kwargs={"function_starts": [main]},
        )
        assert sftp_server_main in cfg.kb.functions
        assert cfg.kb.functions[sftp_server_main].returning is False
        assert sftp_server_main not in cfg.kb.functions[main].block_addrs_set
        assert len(cfg.kb.functions[main].block_addrs_set) < 10

    def test_functions_dispatched_through_a_table_are_kept(self):
        # every handler is a jump table target with no call predecessor, like a cold part of a switch, but it returns
        # on its own and never jumps back into the body of the function that owns the table
        cfg = self._cfg("tailcall_table_dispatch")
        assert set(cfg.kb.functions).issuperset(TABLE_HANDLERS)
        assert all(cfg.kb.functions[addr].returning for addr in TABLE_HANDLERS)
        assert not cfg.kb.functions[TABLE_DECODE].block_addrs_set & TABLE_HANDLERS

    def test_functions_dispatched_through_a_table_without_unwind_data(self):
        # without trusted FDEs the handlers are still recovered: the table is an array of relocated pointers to
        # aligned function entries, which no switch table is
        for kwargs in ({"eh_frame": False}, {"eh_frame_boundaries": False}):
            cfg = self._cfg("tailcall_table_dispatch", **kwargs)
            assert set(cfg.kb.functions).issuperset(TABLE_HANDLERS)
            assert not cfg.kb.functions[TABLE_DECODE].block_addrs_set & TABLE_HANDLERS

    def test_computed_goto_labels_are_not_functions(self):
        # the label table of a computed goto is an array of relocated pointers too, but a label continues its
        # function: it uses the registers that its function set up
        for kwargs in ({}, {"eh_frame": False}, {"eh_frame_boundaries": False}):
            cfg = self._cfg("computed_goto_label_table", **kwargs)
            assert not set(cfg.kb.functions) & COMPUTED_GOTO_LABELS

    def test_computed_goto_labels_inside_an_fde_are_not_functions(self):
        # these labels are entered like functions; only the FDE of dispatch(), which covers them, says they are not
        cfg = self._cfg("computed_goto_stateless_labels")
        assert not set(cfg.kb.functions) & STATELESS_LABELS


class TestEnteredLikeAFunction(unittest.TestCase):
    """
    CFGBase._entered_like_a_function on single x86-64 blocks: a function uses only its arguments, the stack pointer and
    the return address before writing a register, and may only spill other registers to the stack.
    """

    def _entered(self, code: bytes) -> bool:
        proj = angr.Project(
            io.BytesIO(code),
            main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x1000, "entry_point": 0x1000},
            auto_load_libs=False,
        )
        cfg = proj.analyses.CFGFast(normalize=True)
        return cfg._entered_like_a_function(0x1000)

    def test_uses_only_arguments(self):
        assert self._entered(bytes.fromhex("b80a000000c3"))  # mov eax, 10; ret
        assert self._entered(bytes.fromhex("b8010000004801f8c3"))  # mov eax, 1; add rax, rdi; ret

    def test_spills_to_the_stack(self):
        assert self._entered(bytes.fromhex("534889f85bc3"))  # push rbx; mov rax, rdi; pop rbx; ret
        assert self._entered(bytes.fromhex("5089f859c3"))  # push rax; mov eax, edi; pop rcx; ret

    def test_uses_a_register_it_did_not_write(self):
        assert not self._entered(bytes.fromhex("01d8c3"))  # add eax, ebx; ret
        # writing al leaves the upper bytes of rax as they were
        assert not self._entered(bytes.fromhex("b0014801f8c3"))  # mov al, 1; add rax, rdi; ret

    def test_stores_a_register_outside_the_stack(self):
        assert not self._entered(bytes.fromhex("48891fc3"))  # mov [rdi], rbx; ret

    def test_loads_the_callers_stack(self):
        assert not self._entered(bytes.fromhex("488b442408c3"))  # mov rax, [rsp+8]; ret


if __name__ == "__main__":
    unittest.main()
