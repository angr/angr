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


def _value(engine: SimEngineRDAIL, expr) -> claripy.ast.BV:
    result = engine._expr(expr)  # pylint: disable=protected-access
    assert len(result) == expr.bits
    chunks: list[claripy.ast.BV] = []
    for _, values in sorted(result.items(), key=lambda item: item[0]):
        assert len(values) == 1
        value = next(iter(values))
        assert isinstance(value, claripy.ast.BV)
        chunks.append(value)
    return claripy.Concat(*chunks)


def test_extract_and_insert_widths():
    project = angr.load_shellcode(b"\xc3", arch="amd64")
    engine = SimEngineRDAIL(project, FunctionHandler())
    engine.state = cast(ReachingDefinitionsState, _ConstantState())

    base = ailment.Expr.Const(0, 0x0123456789ABCDEF, 64)
    offset = ailment.Expr.Const(1, 0, 64)

    extracted = ailment.Expr.Extract(2, 32, base, offset, Endness.LE)
    assert _value(engine, extracted).concrete_value == 0x89ABCDEF
    widened = ailment.Expr.Convert(3, 32, 64, False, extracted)
    assert _value(engine, widened).concrete_value == 0x89ABCDEF

    inserted = ailment.Expr.Insert(4, base, offset, ailment.Expr.Const(5, 1, 8), Endness.LE)
    assert _value(engine, inserted).concrete_value == 0x0123456789ABCD01
    narrowed = ailment.Expr.Convert(6, 64, 32, False, inserted)
    assert len(engine._expr(narrowed)) == narrowed.bits  # pylint: disable=protected-access

    be_offset = ailment.Expr.Const(7, 1, 64)
    be_extracted = ailment.Expr.Extract(8, 16, base, be_offset, Endness.BE)
    assert _value(engine, be_extracted).concrete_value == 0x2345
    be_inserted = ailment.Expr.Insert(9, base, be_offset, ailment.Expr.Const(10, 0xEE, 8), Endness.BE)
    assert _value(engine, be_inserted).concrete_value == 0x01EE456789ABCDEF
