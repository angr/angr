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


def _engine():
    project = angr.load_shellcode(b"\xc3", arch="amd64")
    engine = SimEngineRDAIL(project, FunctionHandler())
    engine.state = cast(ReachingDefinitionsState, _ConstantState())
    return engine


def test_convert_of_a_partial_read_has_the_target_width():
    engine = _engine()
    base = ailment.Expr.Const(0, 0x0123456789ABCDEF, 64)
    offset = ailment.Expr.Const(1, 0, 64)
    extracted = ailment.Expr.Extract(2, 32, base, offset, Endness.LE)
    widened = engine._expr(ailment.Expr.Convert(3, 32, 64, False, extracted))  # pylint: disable=protected-access
    assert len(widened) == 64 and widened.one_value().concrete_value == 0x89ABCDEF
    inserted = ailment.Expr.Insert(4, base, offset, ailment.Expr.Const(5, 1, 8), Endness.LE)
    narrowed = engine._expr(ailment.Expr.Convert(6, 64, 32, False, inserted))  # pylint: disable=protected-access
    assert len(narrowed) == 32 and narrowed.one_value().concrete_value == 0x89ABCD01


def test_extract_and_insert_address_the_bytes_they_name():
    # little-endian byte offsets count from the least significant byte
    engine = _engine()
    base = ailment.Expr.Const(0, 0x0123456789ABCDEF, 64)

    def value_of(expr):
        result = engine._expr(expr)  # pylint: disable=protected-access
        assert len(result) == expr.bits
        one = result.one_value()
        assert one is not None and not one.symbolic
        return one.concrete_value

    def off(n):
        return ailment.Expr.Const(None, n, 64)

    assert value_of(ailment.Expr.Extract(1, 32, base, off(0), Endness.LE)) == 0x89ABCDEF
    assert value_of(ailment.Expr.Extract(2, 16, base, off(2), Endness.LE)) == 0x89AB
    assert value_of(ailment.Expr.Extract(15, 16, base, off(4), Endness.LE)) == 0x4567
    assert value_of(ailment.Expr.Extract(3, 8, base, off(7), Endness.LE)) == 0x01
    low = ailment.Expr.Insert(4, base, off(0), ailment.Expr.Const(5, 0x33, 8), Endness.LE)
    assert value_of(low) == 0x0123456789ABCD33
    assert value_of(ailment.Expr.Insert(6, base, off(2), ailment.Expr.Const(7, 0xBEEF, 16), Endness.LE)) == (
        0x01234567BEEFCDEF
    )
    assert value_of(ailment.Expr.Insert(8, base, off(4), ailment.Expr.Const(9, 0, 32), Endness.LE)) == 0x89ABCDEF
    # a 32-bit base, as in `K + Insert(x, 0, 33<8>)`: the sum must see 32 bits
    word = ailment.Expr.Const(10, 0x11223344, 32)
    inserted = ailment.Expr.Insert(11, word, off(0), ailment.Expr.Const(12, 33, 8), Endness.LE)
    assert value_of(ailment.Expr.BinaryOp(13, "Add", [ailment.Expr.Const(14, 1, 32), inserted], False)) == 0x11223322
