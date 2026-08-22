from __future__ import annotations

from archinfo import Endness

import angr
from angr.ailment.expression import BinaryOp, Const, Convert, Insert
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import RemoveConstInsert


def test_remove_const_insert_preserves_unwritten_bytes_for_both_endnesses():
    project = angr.load_shellcode(b"\x90", "AMD64")
    manager = Manager()
    optimization = RemoveConstInsert(project, project.kb, manager)

    for endness, offset, expected_base, expected_shift in (
        (Endness.LE, 1, 0x34, 8),
        (Endness.BE, 0, 0x34, 8),
        (Endness.BE, 1, 0x1200, 0),
    ):
        expr = Insert(
            manager.next_atom(),
            Const(manager.next_atom(), 0x1234, 16),
            Const(manager.next_atom(), offset, 64),
            Const(manager.next_atom(), 0x2A, 8),
            endness,
        )

        result = optimization.optimize(expr)

        assert isinstance(result, BinaryOp)
        assert result.op == "Or"
        inserted, preserved = result.operands
        assert isinstance(preserved, Const)
        assert preserved.value == expected_base
        if expected_shift:
            assert isinstance(inserted, BinaryOp)
            assert inserted.op == "Shl"
            assert isinstance(inserted.operands[1], Const)
            assert inserted.operands[1].value == expected_shift
        else:
            assert isinstance(inserted, Convert)
