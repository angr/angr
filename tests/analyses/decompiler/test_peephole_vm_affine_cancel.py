#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import random
import unittest

import networkx

import angr
from angr import claripy
from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import ITE, BinaryOp, Const, Load, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.peephole_optimizations import AffineVVarCancel
from angr.utils.ail import BlockDefs, GraphVVarDefs

from .ail_equivalence import to_claripy


class TestAffineVVarCancel(unittest.TestCase):
    def setUp(self):
        self.m = Manager()
        proj = angr.load_shellcode(b"\x90", "AMD64")
        self.opt = AffineVVarCancel(proj, proj.kb, self.m)

    def v(self, varid):
        return VirtualVariable(self.m.next_atom(), varid, 64, VirtualVariableCategory.TMP, oident=varid)

    def c(self, value):
        return Const(self.m.next_atom(), value & 0xFFFFFFFFFFFFFFFF, 64)

    def op(self, op, a, b):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=64)

    def _defs(self, defs):
        stmts = [Assignment(self.m.next_atom(), self.v(varid), src) for varid, src in defs.items()]
        graph = networkx.DiGraph()
        graph.add_node(Block(0x10, 1, statements=stmts))
        return BlockDefs([], all_defs=GraphVVarDefs(graph))

    def _equal_under(self, defs, a, b):
        constraints = [to_claripy(self.v(varid)) == to_claripy(src) for varid, src in defs.items()]
        return not claripy.Solver().satisfiable(extra_constraints=[*constraints, to_claripy(a) != to_claripy(b)])

    def test_key_spelled_through_two_variables_cancels(self):
        # v2 = v1 ^ K (opaque), v3 = v2 - 5961539, v4 = v3: frame + v4 - v2 + 5961619 is frame + 80
        defs = {2: self.op("Xor", self.v(1), self.c(0x1234)), 3: self.op("Sub", self.v(2), self.c(5961539)), 4: self.v(3)}
        frame = self.v(9)
        expr = self.op("Add", self.op("Sub", self.op("Add", frame, self.v(4)), self.v(2)), self.c(5961619))
        out = self.opt.optimize(expr, block_defs=self._defs(defs))
        assert out is not None and out.likes(self.op("Add", frame, self.c(80)))
        assert self._equal_under(defs, expr, out)

    def test_random_affine_chains(self):
        rng = random.Random(7)
        for _ in range(40):
            k1, k2, k3 = (rng.getrandbits(64) for _ in range(3))
            defs = {
                2: self.op(rng.choice(["Add", "Sub"]), self.v(1), self.c(k1)),
                3: self.op(rng.choice(["Add", "Sub"]), self.v(2), self.c(k2)),
                4: self.v(1),
            }
            a, b = rng.sample([1, 2, 3, 4], 2)
            expr = self.op("Sub", self.op("Add", self.op("Add", self.v(8), self.v(a)), self.c(k3)), self.v(b))
            out = self.opt.optimize(expr, block_defs=self._defs(defs))
            assert out is not None and self._equal_under(defs, expr, out)
            assert "vvar_1" not in str(out) and "vvar_2" not in str(out) and "vvar_3" not in str(out)

    def test_shared_compound_term_cancels(self):
        # v3 = v1 + E and v4 = E with E an opaque term (an ITE inside): v3 - v4 is v1
        def e():
            cond = BinaryOp(self.m.next_atom(), "CmpEQ", [self.v(2), self.c(0)], False, bits=1)
            ite = ITE(self.m.next_atom(), cond, self.c(0), self.c(1024))
            return self.op("Xor", self.op("Or", self.v(2), ite), self.c(26))
        defs = {3: self.op("Add", self.v(1), self.op("Add", e(), self.c(40))), 4: self.op("Sub", e(), self.c(7))}
        expr = self.op("Sub", self.v(3), self.v(4))
        out = self.opt.optimize(expr, block_defs=self._defs(defs))
        assert out is not None and out.likes(self.op("Add", self.v(1), self.c(47)))

    def test_pending_definition_is_not_a_fixpoint(self):
        # v3 still reads memory: nothing cancels yet, but forwarding may make it a sum later
        defs = {3: Load(self.m.next_atom(), self.c(0x1000), 8, "Iend_LE")}
        self.opt.fixpoint_reached = True
        assert self.opt.optimize(self.op("Sub", self.v(3), self.v(1)), block_defs=self._defs(defs)) is None
        assert self.opt.fixpoint_reached is False

    def test_stack_slot_definitions_are_not_expanded(self):
        # a slot whose address a callee may write: its single SSA definition is not built on
        slot = VirtualVariable(self.m.next_atom(), 3, 64, VirtualVariableCategory.STACK, oident=-84)
        stmts = [Assignment(self.m.next_atom(), slot, self.op("Sub", self.v(1), self.v(2)))]
        graph = networkx.DiGraph()
        graph.add_node(Block(0x10, 1, statements=stmts))
        bd = BlockDefs([], all_defs=GraphVVarDefs(graph))
        expr = self.op("Add", self.op("Add", self.op("Xor", self.v(1), self.c(-1)), self.v(2)), slot)
        assert self.opt.optimize(expr, block_defs=bd) is None

    def test_unrelated_or_same_sign_terms_stay(self):
        defs = {2: self.op("Xor", self.v(1), self.c(5)), 3: self.op("Add", self.v(1), self.c(5))}
        bd = self._defs(defs)
        # v2 is not v1 plus a constant
        assert self.opt.optimize(self.op("Sub", self.v(2), self.v(1)), block_defs=bd) is None
        # both added: nothing cancels
        assert self.opt.optimize(self.op("Add", self.v(3), self.v(1)), block_defs=bd) is None
        # no graph definitions
        assert self.opt.optimize(self.op("Sub", self.v(3), self.v(1)), block_defs=BlockDefs([])) is None


if __name__ == "__main__":
    unittest.main()
