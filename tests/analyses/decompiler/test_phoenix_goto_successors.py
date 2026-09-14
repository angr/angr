#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import re
import unittest

import angr
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestPhoenixGotoSuccessors(unittest.TestCase):
    """
    bzip2's BZ2_decompress is a resumable state machine: a switch whose cases jump into loops that other cases
    share, and loops that leave through gotos to a shared error block. Things that used to break it: a region's
    finalize() re-established the edge for a loop exit that cyclic refinement had already turned into a goto; the
    jump-table dispatch kept structural edges to case labels buried inside loops (goto-only cases), which misled
    last-resort refinement and left the switch with one successor per such label; cyclic refinement picked the
    shared error block as a loop successor by address and cut off the loop nest that followed; and a while loop
    whose successor RegionIdentifier had absorbed into the loop region was not recognized as a while loop. The
    output then kept a fraction of the function.
    """

    def _decompile_bzip2_decompress(self, binary_name: str):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", binary_name)
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions.function(name="BZ2_decompress")
        assert func is not None

        incomplete = []

        class _Watch(logging.Handler):
            def emit(self, record):
                if "Structuring failed to complete" in record.getMessage():
                    incomplete.append(record)

        logger = logging.getLogger("angr.analyses.decompiler.structuring.recursive_structurer")
        watch = _Watch()
        logger.addHandler(watch)
        try:
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        finally:
            logger.removeHandler(watch)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert not incomplete

        # every block with real instructions must be reachable from the output. the blocks left out are jump-only
        # and nop blocks plus the stack-protector check, which the decompiler removes.
        covered = set()
        for element in dec.codegen.map_pos_to_addr.values():
            tags = getattr(element.obj, "tags", None)
            if tags and tags.get("ins_addr") is not None:
                covered.add(tags["ins_addr"])
        blocks = list(func.blocks)
        missing = [b for b in blocks if not (set(b.instruction_addrs) & covered)]
        return dec.codegen.text, len(blocks), missing

    def test_bzip2_o2_decompress_structures_completely(self):
        text, nblocks, missing = self._decompile_bzip2_decompress("decbench_bzip2_O2_noinline")
        assert nblocks > 450
        assert len(missing) <= 30, [hex(b.addr) for b in missing]
        assert text.count("case ") >= 40
        # the GET_BITS loops are emitted as while or for loops
        assert len(re.findall(r"\b(while|for) \(", text)) >= 60

    def test_bzip2_o0_decompress_structures_completely(self):
        text, nblocks, missing = self._decompile_bzip2_decompress("decbench_bzip2_O0")
        assert nblocks > 500
        assert len(missing) <= 35, [hex(b.addr) for b in missing]
        assert text.count("case ") >= 40
        assert len(re.findall(r"\b(while|for) \(", text)) >= 60


if __name__ == "__main__":
    unittest.main()
