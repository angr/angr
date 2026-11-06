from __future__ import annotations

import os
import unittest

import angr
from angr.ailment import Manager
from angr.ailment.expression import BinaryOp, Const
from angr.analyses.decompiler.ssailification.rewriting_engine import SimEngineSSARewriting
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestSSAILificationRewriting(unittest.TestCase):
    def test_binaryop_preserves_vector_metadata(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        m = Manager()

        engine = SimEngineSSARewriting(
            proj,
            ail_manager=m,
            def_to_udef={},
            incomplete_defs=set(),
        )

        original_op0 = Const(m.next_atom(), 1, 128)
        original_op1 = Const(m.next_atom(), 2, 128)
        expr = BinaryOp(
            m.next_atom(),
            "InterleaveLOV",
            [original_op0, original_op1],
            False,
            bits=128,
            vector_count=16,
            vector_size=8,
        )

        replacement = Const(m.next_atom(), 3, 128)

        original_expr = engine._expr
        calls = iter([replacement, None])
        try:
            engine._expr = lambda operand: next(calls)
            out = engine._handle_expr_BinaryOp(expr)
        finally:
            engine._expr = original_expr

        assert isinstance(out, BinaryOp)
        assert out.operands[0] == replacement
        assert out.operands[1] == original_op1
        assert out.vector_count == 16
        assert out.vector_size == 8
