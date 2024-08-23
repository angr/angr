# pylint:disable=no-self-use,arguments-renamed
from __future__ import annotations
from collections import OrderedDict

import ailment

from ..structuring.structurer_nodes import SwitchCaseNode
from ..sequence_walker import SequenceWalker


class SwitchExpressionSimplifier(SequenceWalker):
    """
    Identifies switch expressions that adds or minuses a constant, removes the constant from the switch expression, and
    adjust all case expressions accordingly.
    """

    def __init__(self, node):
        handlers = {
            SwitchCaseNode: self._handle_SwitchCase,
        }
        super().__init__(handlers)

        self.walk(node)

    def _handle_SwitchCase(self, node: SwitchCaseNode, **kwargs):
        changed = False

        switch_expr = node.switch_expr
        convert = None

        # pylint: disable=import-outside-toplevel
        from ..peephole_optimizations.remove_noop_conversions import RemoveNoopConversions

        while isinstance(switch_expr, ailment.Expr.Convert):
            optimized = RemoveNoopConversions(None, None).optimize(switch_expr)
            if optimized is not None:
                switch_expr = optimized
                continue

            convert = switch_expr
            switch_expr = switch_expr.operand

        if (
            isinstance(switch_expr, ailment.Expr.BinaryOp)
            and switch_expr.op in {"Add", "Sub"}
            and isinstance(switch_expr.operands[1], ailment.Expr.Const)
        ):
            v = switch_expr.operands[1].value
            if switch_expr.op == "Add":
                v = -v

            new_switch_expr = switch_expr.operands[0]
            if convert is not None:
                # unpack if necessary
                if isinstance(new_switch_expr, ailment.Expr.Convert):
                    if new_switch_expr.to_bits == convert.from_bits:
                        new_switch_expr = new_switch_expr.operand
                    else:
                        new_switch_expr = ailment.Expr.Convert(
                            None,
                            new_switch_expr.from_bits,
                            convert.to_bits,
                            convert.is_signed,
                            new_switch_expr.operand,
                            **convert.tags,
                        )
                else:
                    new_switch_expr = ailment.Expr.Convert(
                        None, convert.from_bits, convert.to_bits, convert.is_signed, new_switch_expr, **convert.tags
                    )

            new_cases = OrderedDict()
            for case_idx, case_node in node.cases.items():
                if isinstance(case_idx, int):
                    new_cases[case_idx + v] = case_node
                elif isinstance(case_idx, tuple):
                    new_cases[tuple(idx_ + v for idx_ in case_idx)] = case_node
                else:
                    raise TypeError(f"Unsupported case_idx type {type(case_idx)}")
            new_node = SwitchCaseNode(new_switch_expr, new_cases, default_node=node.default_node, addr=node.addr)
            node = new_node
            changed = True

        r = super()._handle_SwitchCase(node, **kwargs)
        if changed and r is None:
            return node
        return r
