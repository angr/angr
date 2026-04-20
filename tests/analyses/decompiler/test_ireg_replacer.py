"""Unit tests for IRegReplacer optimization pass engine."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.expression import Const, IRegister, Register, Tmp
from angr.ailment.statement import Assignment
from angr.ailment.block import Block
from angr.analyses.decompiler.optimization_passes.ireg_replacer import IRegReplacerEngine
from angr.analyses.decompiler.optimization_passes.engine_base import SimplifierAILState


def _make_proj():
    return angr.load_shellcode(b"\xc3", "amd64")


class TestIRegReplacerEngine(unittest.TestCase):
    """Test IRegReplacer engine resolves and cleans IRegisters."""

    def test_resolve_const_ireg_in_assignment_dst(self):
        """Assignment(dst=IRegister(Const), src=data) -> Assignment(dst=Register, src=data)."""
        proj = _make_proj()
        engine = IRegReplacerEngine(proj)
        state = SimplifierAILState(proj.arch)

        # IRegister with ftop=-1 (0xffffffff) in fpreg array -> offset 960 (mm7)
        ix = Const(1, None, 0xFFFFFFFF, 32)
        ireg = IRegister(2, None, ix, 64, array_base=904, array_nElems=8, array_shift=3)
        data = Const(3, None, 42, 64)
        stmt = Assignment(0, ireg, data, ins_addr=0x1000)

        block = Block(0x1000, 0, statements=[stmt])
        result = engine.process(state=state, block=block)

        assert len(result.statements) == 1
        result_stmt = result.statements[0]
        assert isinstance(result_stmt, Assignment)
        assert isinstance(result_stmt.dst, Register)
        assert result_stmt.dst.reg_offset == 960

    def test_resolve_const_ireg_in_expression(self):
        """IRegister(Const) in an expression should resolve to Register."""
        proj = _make_proj()
        engine = IRegReplacerEngine(proj)
        state = SimplifierAILState(proj.arch)

        # IRegister as src in an assignment
        ix = Const(1, None, 0, 32)  # ftop=0 -> offset 904
        ireg = IRegister(2, None, ix, 64, array_base=904, array_nElems=8, array_shift=3)
        dst = Register(3, None, 16, 64)  # rax
        stmt = Assignment(0, dst, ireg, ins_addr=0x1000)

        block = Block(0x1000, 0, statements=[stmt])
        result = engine.process(state=state, block=block)

        result_stmt = result.statements[0]
        assert isinstance(result_stmt.src, Register)
        assert result_stmt.src.reg_offset == 904

    def test_unresolvable_ireg_assignment_stripped(self):
        """Assignment(dst=IRegister(Tmp), src=data) should be stripped (dead fptag write)."""
        proj = _make_proj()
        engine = IRegReplacerEngine(proj)
        state = SimplifierAILState(proj.arch)

        # IRegister with non-Const offset (unresolvable)
        tmp = Tmp(1, None, 5, 32)
        ireg = IRegister(2, None, tmp, 8, array_base=968, array_nElems=8, array_shift=0)
        data = Const(3, None, 0, 8)
        stmt = Assignment(0, ireg, data, ins_addr=0x1000)

        # Also add a normal statement to ensure it survives
        normal = Assignment(1, Register(4, None, 16, 64), Const(5, None, 99, 64), ins_addr=0x1000)

        block = Block(0x1000, 0, statements=[stmt, normal])

        # The engine won't resolve the IRegister (non-Const offset),
        # but the IRegReplacer._analyze cleanup strips unresolved IRegister assignments.
        # Here we test just the engine -- the cleanup is in the pass itself.
        result = engine.process(state=state, block=block)

        # The engine leaves unresolvable IRegisters as-is
        ireg_stmts = [s for s in result.statements if isinstance(s, Assignment) and isinstance(s.dst, IRegister)]
        assert len(ireg_stmts) == 1  # still present (engine doesn't strip)

    def test_fptag_resolution(self):
        """IRegister for fptag (base=968, shift=0, 1-byte) resolves correctly."""
        proj = _make_proj()
        engine = IRegReplacerEngine(proj)
        state = SimplifierAILState(proj.arch)

        ix = Const(1, None, 3, 32)  # ftop=3
        ireg = IRegister(2, None, ix, 8, array_base=968, array_nElems=8, array_shift=0)
        data = Const(3, None, 1, 8)
        stmt = Assignment(0, ireg, data, ins_addr=0x1000)

        block = Block(0x1000, 0, statements=[stmt])
        result = engine.process(state=state, block=block)

        result_stmt = result.statements[0]
        assert isinstance(result_stmt.dst, Register)
        assert result_stmt.dst.reg_offset == 968 + 3  # fptag[3]


if __name__ == "__main__":
    unittest.main()
