# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import os
import subprocess
import sys
import unittest

import angr
from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort
from angr.knowledge_plugins.xrefs import XRef, XRefManager, XRefType
from angr.rustylib import SegmentList
from tests.common import bin_location

_HASH_SNIPPET = (
    "from angr.knowledge_plugins.xrefs import XRef, XRefType;"
    "print(hash(XRef(ins_addr=0x4015a8, block_addr=0x4015a8, stmt_idx=3, dst=0x606fe0, xref_type=XRefType.Offset)))"
)


class _ListOrderedXRefManager(XRefManager):
    """Returns xrefs in a fixed order so the test does not depend on set iteration order."""

    def get_xrefs_by_dst(self, dst):
        return sorted(super().get_xrefs_by_dst(dst), key=lambda r: -r.ins_addr)


class TestXRefs(unittest.TestCase):
    def test_hash_is_value_only(self):
        ref = XRef(ins_addr=0x4015A8, block_addr=0x4015A8, stmt_idx=3, dst=0x606FE0, xref_type=XRefType.Offset)
        assert hash(ref) == hash((XRefType.Offset, 0x4015A8, 0x606FE0))
        assert hash(ref) == hash(ref.copy())

    def test_hash_stable_across_processes(self):
        env = dict(os.environ, PYTHONHASHSEED="12345")
        out = subprocess.check_output([sys.executable, "-c", _HASH_SNIPPET], env=env, stderr=subprocess.DEVNULL)
        assert int(out) == hash((XRefType.Offset, 0x4015A8, 0x606FE0))

    def test_guess_data_type_got_plt_entry_any_xref_order(self):
        proj = angr.Project(os.path.join(bin_location, "tests", "x86_64", "true"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        plt_stub = 0x4015A8  # __cxa_finalize@plt reads the .got slot at 0x606fe0
        assert plt_stub in proj.loader.main_object.reverse_plt
        xrefs = _ListOrderedXRefManager(proj.kb)
        # the non-PLT reader comes first; the PLT reader must still win
        xrefs.add_xref(
            XRef(ins_addr=0x401739, block_addr=0x401739, stmt_idx=1, dst=0x606FE0, xref_type=XRefType.Offset)
        )
        xrefs.add_xref(
            XRef(ins_addr=plt_stub, block_addr=plt_stub, stmt_idx=1, dst=0x606FE0, xref_type=XRefType.Offset)
        )
        sort, size = cfg.model._guess_data_type(0x606FE0, 8, xrefs=xrefs, seg_list=SegmentList())
        assert sort == MemoryDataSort.GOTPLTEntry
        assert size == 8
        assert cfg.model.memory_data[0x606FE0].sort == MemoryDataSort.GOTPLTEntry


if __name__ == "__main__":
    unittest.main()
