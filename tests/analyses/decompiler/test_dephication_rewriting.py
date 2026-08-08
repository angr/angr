#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.ailment import Manager
from angr.ailment.expression import Const, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.dephication.rewriting_engine import SimEngineDephiRewriting
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestDephicationRewriting(unittest.TestCase):
    """
    Dephication remaps every vvar feeding a phi onto the phi's destination and then drops the phi. If a remapped
    destination is not written back, the phi destination ends up with no definition and the phi sources with no uses,
    which passes that reason about vvar uses read as dead code.
    """

    @staticmethod
    def _engine(mapping):
        # a project is only needed for the arch; no CFG or analyses required
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        return proj, SimEngineDephiRewriting(proj, mapping)

    def test_remapped_dst_survives_non_vvar_src(self):
        proj, engine = self._engine({2759: 1330})
        m = Manager(arch=proj.arch)
        stmt = Assignment(
            m.next_atom(),
            VirtualVariable(m.next_atom(), 2759, 64, VirtualVariableCategory.REGISTER),
            # a source that is not a bare vvar; this is what used to discard the remapped destination
            UnaryOp(
                m.next_atom(),
                "Reference",
                VirtualVariable(m.next_atom(), 4575, 128, VirtualVariableCategory.STACK),
                bits=64,
            ),
            ins_addr=0x400100,
        )

        out = engine._handle_stmt_Assignment(stmt)
        assert isinstance(out, Assignment)
        assert out.dst.varid == 1330

    def test_remapped_dst_survives_const_src(self):
        proj, engine = self._engine({7: 3})
        m = Manager(arch=proj.arch)
        stmt = Assignment(
            m.next_atom(),
            VirtualVariable(m.next_atom(), 7, 64, VirtualVariableCategory.REGISTER),
            Const(m.next_atom(), 0x1234, 64),
            ins_addr=0x400100,
        )

        out = engine._handle_stmt_Assignment(stmt)
        assert isinstance(out, Assignment)
        assert out.dst.varid == 3

    def test_self_assignment_is_still_dropped(self):
        # the reason the return used to sit behind the both-sides-are-vvars guard: once both sides map onto the same
        # variable the statement is a no-op and has to go away
        proj, engine = self._engine({11: 3, 12: 3})
        m = Manager(arch=proj.arch)
        stmt = Assignment(
            m.next_atom(),
            VirtualVariable(m.next_atom(), 11, 64, VirtualVariableCategory.REGISTER),
            VirtualVariable(m.next_atom(), 12, 64, VirtualVariableCategory.REGISTER),
            ins_addr=0x400100,
        )

        assert engine._handle_stmt_Assignment(stmt) == ()

    def test_unmapped_assignment_is_left_alone(self):
        proj, engine = self._engine({2759: 1330})
        m = Manager(arch=proj.arch)
        stmt = Assignment(
            m.next_atom(),
            VirtualVariable(m.next_atom(), 99, 64, VirtualVariableCategory.REGISTER),
            Const(m.next_atom(), 1, 64),
            ins_addr=0x400100,
        )

        # None means "unchanged" to the caller, which then keeps the original statement
        assert engine._handle_stmt_Assignment(stmt) is None

    def test_bbbq_rust_flavor_keeps_string_constants(self):
        """
        sub_410920 sets up a &str in a block whose only outward effect flows through a phi. With the remapped
        destination dropped, RedundantBlockRemover deleted the block and the string with it.
        """
        bin_path = os.path.join(test_location, "x86_64", "bbbq")
        # the window has to reach past the function: with a tighter scope the callee prototypes differ enough that the
        # block holding this string survives even with the bug, and the test stops testing anything
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x410920, window=0x4000, expand_call_tree=False, run_ccc=False
        )
        proj.analyses.RustSymbolRecovery()
        proj.analyses.TypeDBLoader()
        dec = proj.analyses.Decompiler(0x410920, cfg=cfg.model, flavor="rust", fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert "seed_hex is not valid hex" in dec.codegen.text


if __name__ == "__main__":
    unittest.main()
