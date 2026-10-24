# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import re
import unittest

import angr
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")


class TestStructuringDecBenchCoreutils(unittest.TestCase):
    """
    Phoenix structuring failures on stripped DecBench coreutils/gzip binaries (x86-64, PIE, angr base 0x400000).
    Every function here used to leave a partial result in Decompiler.structuring_failures.
    """

    @staticmethod
    def _decompile(binary: str, addr: int) -> tuple[angr.analyses.Decompiler, str]:
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "x86_64", binary),
            addr,
            include_plt=True,
            expand_call_tree=False,
            project_kwargs={"auto_load_libs": False},
            cfg_kwargs={"normalize": True},
            run_ccc=False,
        )
        dec = proj.analyses.Decompiler(proj.kb.functions[addr], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert dec.structuring_failures == [], f"structuring failed at {[hex(a) for a in dec.structuring_failures]}"
        return dec, dec.codegen.text

    def test_attach_switch_head_case_virtualized(self):
        # gnulib attach(): a two-case lowered switch whose "\0" case enters a rotated loop at its condition. the
        # virtualized case must stay a switch case, and the goto into the loop must not be mistaken for the end of
        # the switch (it became a wrong "break")
        _, text = self._decompile("decbench_coreutils_dir_O2_noinline_stripped", 0x406140)
        assert "= 47" in text and re.search(r"while \(\*(\(char \*\))?\w+\)", text)
        assert "break;" not in text

    def test_get_funky_string_irreducible_state_machine(self):
        # dircolors get_funky_string(): threaded state machine; last-resort refinement used to orphan the hex loop
        _, text = self._decompile("decbench_coreutils_dir_O2_noinline_stripped", 0x405740)
        assert "= 127" in text and "goto LABEL_40578b;" in text

    def test_tty_main_getopt_switch_continue_case(self):
        # getopt_long loop whose lowered switch has a case jumping back to the loop head
        _, text = self._decompile("decbench_coreutils_tty_O2_noinline_stripped", 0x402600)
        assert "while (1)" in text and "switch (" in text
        assert "ttyname(0)" in text and "isatty(0)" in text and "extra operand" in text

    def test_seq_main_shared_noreturn_tail(self):
        # usage(1) is a shared noreturn tail: the loop region keeps an extra exit to it, and last-resort refinement
        # must virtualize that exit rather than the sibling branches' jumps to the same tail
        _, text = self._decompile("decbench_coreutils_seq_O2_noinline_stripped", 0x402760)
        assert "missing operand" in text and "extra operand" in text
        assert "LABEL_4029f9:" in text and "goto LABEL_4029f9;" in text

    def test_cat_main_absorbed_loop_exit_kept(self):
        # the loop exit absorbed by an ITE inside the failed loop region must stay visible to the parent
        _, text = self._decompile("decbench_coreutils_cat_O2_noinline_stripped", 0x403130)
        assert "write error" in text and "cannot do ioctl on %s" in text and "return v" in text

    def test_shred_dopass(self):
        _, text = self._decompile("decbench_coreutils_shred_O2_noinline_stripped", 0x403A20)
        assert "pass %lu/%lu" in text and "cannot rewind" in text and "file too large" in text

    def test_ptx_find_occurs_in_text_minus_one_case(self):
        # re_search result switch: a "-1" case that is not the cascade head must stay a case
        _, text = self._decompile("decbench_coreutils_ptx_O0_stripped", 0x403A06)
        assert "re_search(" in text and "case 4294967294:" in text and "case 4294967295:" in text

    def test_gzip_printf_parse(self):
        # the flags loop and the length-modifier loop have a peeled first test, so each is entered twice; the
        # irreducible-loop slice used to swallow the enclosing directive loop. every flag case must still jump back
        # into the flags loop
        _, text = self._decompile("decbench_gzip_O2_noinline_stripped", 0x410DD0)
        assert "while (1)" in text and "== 37" in text and "case 108:" in text
        assert re.search(r"case 73:\s*\n.*\n\s*goto LABEL_410fc8;", text)
        assert re.search(r"case 76:\s*\n.*\n\s*goto LABEL_410fa3;", text)

    def test_tar_parse_transform_expr_private_loop_exits(self):
        # absorbing private loop exits one at a time added their successors as new exits; the partial absorption
        # left stale outgoing marks that disconnected the function
        _, text = self._decompile("decbench_tar_O2_noinline_stripped", 0x42F9F0)
        assert text.count("while (") + text.count("for (") >= 2
        assert "memcpy(" in text

    def test_gzip_vasnprintf_switch_in_nested_loop_breaks_to_outer_latch(self):
        # the directive loop is entered twice (0x410352 is a goto). its inner loop holds the conversion switch, and
        # once the nest is refined at the root, that loop breaks to the outer latch: a marked edge that must not
        # make the switch-case construction think the latch will dangle
        _, text = self._decompile("decbench_gzip_O2_noinline_stripped", 0x40F880)
        assert "goto LABEL_410352;" in text and "LABEL_410352:" in text
        assert "switch (" in text and "abort();" in text
        assert text.count("while (1)") >= 3


if __name__ == "__main__":
    unittest.main()
