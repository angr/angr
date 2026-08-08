from __future__ import annotations

from typing import cast

from archinfo import Endness

import angr
from angr import ailment, claripy
from angr.analyses.reaching_definitions.engine_ail import SimEngineRDAIL
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState


class _ConstantState:
    class _CodeLocation:
        context = None

    codeloc = _CodeLocation()

    @staticmethod
    def mark_const(_value: int, _size: int) -> None:
        pass

    @staticmethod
    def top(bits: int) -> claripy.ast.BV:
        return claripy.BVS("TOP", bits)

    @staticmethod
    def annotate_with_def(value: claripy.ast.BV, _definition) -> claripy.ast.BV:
        return value

    @staticmethod
    def add_memory_use_by_def(_definition, *, expr) -> None:
        pass


def test_convert_handles_operand_width_mismatches():
    project = angr.load_shellcode(b"\xc3", arch="amd64")
    engine = SimEngineRDAIL(project, FunctionHandler())
    engine.state = cast(ReachingDefinitionsState, _ConstantState())

    base = ailment.Expr.Const(0, 0x0123456789ABCDEF, 64)
    offset = ailment.Expr.Const(1, 0, 64)

    extracted = ailment.Expr.Extract(2, 32, base, offset, Endness.LE)
    widened = ailment.Expr.Convert(3, 32, 64, False, extracted)
    widened_result = engine._expr(widened)  # pylint: disable=protected-access
    assert len(widened_result) == widened.bits
    widened_value = widened_result.one_value()
    assert widened_value is not None and widened_value.symbolic

    inserted = ailment.Expr.Insert(4, base, offset, ailment.Expr.Const(5, 1, 8), Endness.LE)
    narrowed = ailment.Expr.Convert(6, 64, 32, False, inserted)
    narrowed_result = engine._expr(narrowed)  # pylint: disable=protected-access
    assert len(narrowed_result) == narrowed.bits
    narrowed_value = narrowed_result.one_value()
    assert narrowed_value is not None and narrowed_value.symbolic
