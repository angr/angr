from typing import Any, Optional, TYPE_CHECKING
from collections.abc import Iterable, Generator

import claripy
import ailment

if TYPE_CHECKING:
    from ...code_location import CodeLocation


class Detail:
    """
    A companion class used together with PropValue. It describes stored information at each offset (in bytes).

    :ivar def_at:   Where this expression is defined, or None if it was never explicitly defined in the current block
                    or the current function.
    """

    __slots__ = ("size", "expr", "def_at")

    def __init__(self, size: int, expr: ailment.Expression | None, def_at: Optional["CodeLocation"]):
        self.size = size
        self.expr = expr
        self.def_at = def_at

    def __repr__(self) -> str:
        return f"{self.size:x}: {self.expr}@{self.def_at}"


# The base value


class PropValue:
    """
    Describes immutable basic value type that is used in Propagator.
    """

    __slots__ = (
        "value",
        "offset_and_details",
    )

    def __init__(self, value: claripy.ast.Bits, offset_and_details: dict[int, Detail] | None = None):
        self.value = value
        self.offset_and_details = offset_and_details

    @property
    def needs_details(self):
        return not bool(self.offset_and_details)

    @property
    def one_expr(self) -> ailment.Expression | None:
        """
        Get the expression that starts at offset 0 and covers the entire PropValue. Returns None if there are no
        expressions or multiple expressions.
        """
        if self.offset_and_details and len(self.offset_and_details) == 1:
            if 0 in self.offset_and_details:
                detail = self.offset_and_details[0]
                if detail.size == self.value.size() // 8:
                    return detail.expr
        return None

    @property
    def one_defat(self) -> Optional["CodeLocation"]:
        """
        Get the definition location of the expression that starts at offset 0 and covers the entire PropValue. Returns
        None if there are no expressions or multiple expressions.
        """
        if self.offset_and_details and len(self.offset_and_details) == 1:
            if 0 in self.offset_and_details:
                detail = self.offset_and_details[0]
                if detail.size == self.value.size() // 8:
                    return detail.def_at
        return None

    def to_label(self):
        raise NotImplementedError()

    def with_details(self, size: int, expr: ailment.Expression, def_at: "CodeLocation") -> "PropValue":
        return PropValue(self.value, offset_and_details={0: Detail(size, expr, def_at)})

    def all_exprs(self) -> Generator[ailment.Expression, None, None]:
        if not self.offset_and_details:
            return
        for detail in self.offset_and_details.values():
            yield detail.expr

    def non_zero_exprs(self) -> Generator[ailment.Expression, None, None]:
        if not self.offset_and_details:
            return
        for detail in self.offset_and_details.values():
            if isinstance(detail.expr, ailment.Expr.Const) and detail.expr.value == 0:
                continue
            yield detail.expr

    @staticmethod
    def chop_value(value: claripy.ast.Bits, begin_offset, end_offset) -> claripy.ast.Bits:
        if begin_offset == end_offset:
            chop_start = value.size() - begin_offset * 8 - 1
            chop_end = value.size() - end_offset * 8 - 1
        else:
            chop_start = value.size() - begin_offset * 8 - 1
            chop_end = value.size() - end_offset * 8
        if chop_end - chop_start + 1 == value.size():
            # fast path: no chopping
            return value
        if isinstance(value, claripy.ast.FP):
            # converting the FP value to an AST so that we can chop
            value = claripy.fpToIEEEBV(value)
        return value[chop_start:chop_end]

    def value_and_labels(self) -> Generator[tuple[int, claripy.ast.Bits, int, dict | None], None, None]:
        if not self.offset_and_details:
            return
        keys = list(sorted(self.offset_and_details.keys()))
        if keys[0] != 0:
            # missing details at 0
            yield 0, self.chop_value(self.value, 0, keys[0]), keys[0], None

        end_offset = 0
        for idx, offset in enumerate(keys):
            detail = self.offset_and_details[offset]
            end_offset = offset + detail.size
            label = {"expr": detail.expr, "def_at": detail.def_at}
            yield offset, self.chop_value(self.value, offset, end_offset), end_offset - offset, label

            # gap detection
            if idx != len(keys) - 1:
                next_offset = keys[idx + 1]
                if end_offset != next_offset:
                    yield end_offset, self.chop_value(
                        self.value, end_offset, next_offset
                    ), next_offset - end_offset, None

        # final gap detection
        if end_offset < self.value.size() // 8:
            yield end_offset, self.chop_value(
                self.value, end_offset, self.value.size() // 8
            ), self.value.size() // 8 - end_offset, None

    @staticmethod
    def from_value_and_labels(
        value: claripy.ast.Bits, labels: Iterable[tuple[int, int, int, dict[str, Any]]]
    ) -> "PropValue":
        if not labels:
            return PropValue(value)
        offset_and_details = {}
        for offset, offset_in_expr, size, label in labels:
            expr = label["expr"]
            if expr is not None:
                if offset_in_expr != 0:
                    expr = PropValue.extract_ail_expression(offset_in_expr * 8, size * 8, expr)
                elif size < expr.size:
                    expr = PropValue.extract_ail_expression(0, size * 8, expr)
                elif size > expr.size:
                    expr = PropValue.extend_ail_expression((size - expr.size) * 8, expr)
            offset_and_details[offset] = Detail(size, expr, label["def_at"])
        return PropValue(value, offset_and_details=offset_and_details)

    @staticmethod
    def from_value_and_details(value: claripy.ast.Bits, size: int, expr: ailment.Expression, def_at: "CodeLocation"):
        d = Detail(size, expr, def_at)
        return PropValue(value, offset_and_details={0: d})

    @staticmethod
    def extract_ail_expression(
        start: int, bits: int, expr: ailment.Expr.Expression | None
    ) -> ailment.Expr.Expression | None:
        if expr is None:
            return None

        if isinstance(expr, ailment.Expr.Const):
            mask = (1 << bits) - 1
            return ailment.Expr.Const(expr.idx, expr.variable, (expr.value >> start) & mask, bits, **expr.tags)

        if start == 0:
            return ailment.Expr.Convert(None, expr.bits, bits, False, expr, **expr.tags)
        else:
            a = ailment.Expr.BinaryOp(
                None, "Shr", (expr, ailment.Expr.Const(None, None, bits, expr.bits)), False, **expr.tags
            )
            return ailment.Expr.Convert(None, a.bits, bits, False, a, **expr.tags)

    @staticmethod
    def extend_ail_expression(bits: int, expr: ailment.Expr.Expression | None) -> ailment.Expr.Expression | None:
        if expr is None:
            return None
        if isinstance(expr, ailment.Expr.Const):
            return ailment.Expr.Const(expr.idx, expr.variable, expr.value, bits + expr.bits, **expr.tags)
        elif isinstance(expr, ailment.Expr.Convert):
            return ailment.Expr.Convert(None, expr.from_bits, bits + expr.to_bits, False, expr.operand, **expr.tags)
        return ailment.Expr.Convert(None, expr.bits, bits + expr.bits, False, expr, **expr.tags)
