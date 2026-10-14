# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
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
        assert "= 47" in text and "while (*(char *)" in text
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

    def test_shred_dopass(self):
        _, text = self._decompile("decbench_coreutils_shred_O2_noinline_stripped", 0x403A20)
        assert "pass %lu/%lu" in text and "cannot rewind" in text and "file too large" in text

    def test_ptx_find_occurs_in_text_minus_one_case(self):
        # re_search result switch: a "-1" case that is not the cascade head must stay a case
        _, text = self._decompile("decbench_coreutils_ptx_O0_stripped", 0x403A06)
        assert "re_search(" in text and "case 4294967294:" in text and "case 4294967295:" in text


if __name__ == "__main__":
    unittest.main()
