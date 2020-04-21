
import logging

import ailment

from ... import AnalysesHub
from .optimization_pass import OptimizationPass


_l = logging.getLogger(name=__name__)


def s2u(s, bits):
    if s > 0:
        return s
    return (1 << bits) + s


class StackCanarySimplifier(OptimizationPass):

    ARCHES = ["X86", "AMD64"]
    PLATFORMS = ["linux"]

    def __init__(self, func, blocks, graph):

        super().__init__(func, blocks=blocks, graph=graph)

        self.analyze()

    def _check(self):
        # Check the first block and see if there is any statement reading data from fs:0x28h
        init_stmt = self._find_canary_init_stmt()

        return init_stmt is not None, {'init_stmt': init_stmt}

    def _analyze(self, cache=None):

        init_stmt = None
        if cache is not None:
            init_stmt = cache.get('init_stmt', None)

        if init_stmt is None:
            init_stmt = self._find_canary_init_stmt()

        if init_stmt is None:
            return

        # Look for the statement that loads back canary value from the stack
        first_block, stmt_idx = init_stmt
        canary_init_stmt = first_block.statements[stmt_idx]
        # where is the stack canary stored?
        if not isinstance(canary_init_stmt.addr, ailment.Expr.StackBaseOffset):
            _l.debug("Unsupported canary storing location %s. Expects an ailment.Expr.StackBaseOffset.",
                     canary_init_stmt.addr)
            return

        store_offset = canary_init_stmt.addr.offset
        if not isinstance(store_offset, int):
            _l.debug("Unsupported canary storing offset %s. Expects an int.", store_offset)

        # The function should end with an if-else statement
        # Find all nodes with 0 out-degrees
        end_nodes = [ self._get_block(node.addr) for node in self._func.graph.nodes()
                      if self._func.graph.out_degree(node) == 0 ]

        if len(end_nodes) != 2:
            _l.debug("This function has more than two end nodes. Maybe we can add support to it in the future.")
            return

        # One of the end nodes calls __stack_chk_fail
        stack_chk_fail_caller = None
        for end_node in end_nodes:
            if self._calls_stack_chk_fail(end_node):
                stack_chk_fail_caller = end_node
                break
        else:
            _l.debug("Cannot find the node that calls __stack_chk_fail().")
            return

        # All end nodes have one common predecessor
        preds = set()
        for node in end_nodes:
            preds |= set(self._func.graph.predecessors(self._func.get_node(node.addr)))

        if len(preds) != 1:
            _l.debug("End nodes have %d predecessors. Expects 1.", len(preds))
            return

        pred = self._get_block(next(iter(preds)).addr)

        if len(pred.statements) < 1:
            _l.debug("The predecessor node is empty.")
            return

        # Check the last statement
        if not isinstance(pred.statements[-1], ailment.Stmt.ConditionalJump):
            _l.debug("The predecessor does not end with a conditional jump.")
            return

        # Find the statement that computes real canary value xor stored canary value
        canary_check_stmt_idx = self._find_canary_xor_stmt(pred, store_offset)
        if canary_check_stmt_idx is None:
            _l.debug("Cannot find the canary check statement in the predecessor.")
            return

        # Awesome. Now patch this function.

        # Patch the pred so that it jumps to the one that is not stack_chk_fail_caller
        other_node = next(iter([ end_node for end_node in end_nodes if end_node is not stack_chk_fail_caller ]))
        pred_copy = pred.copy()
        pred_copy.statements[-1] = ailment.Stmt.Jump(len(pred_copy.statements) - 1,
                                                     ailment.Expr.Const(None, None, other_node.addr,
                                                                        self.project.arch.bits),
                                                     ins_addr=pred_copy.statements[-1].ins_addr,
                                                     )

        self._update_block(pred, pred_copy)

        # Remove the block that calls stack_chk_fail_caller
        self._remove_block(stack_chk_fail_caller)

        # Remove the statement that loads the stack canary from fs
        first_block_copy = first_block.copy()
        first_block_copy.statements.pop(stmt_idx)
        self._update_block(first_block, first_block_copy)

        # Done!

    def _find_canary_init_stmt(self):

        first_block = self._get_block(self._func.addr)

        for idx, stmt in enumerate(first_block.statements):
            if isinstance(stmt, ailment.Stmt.Store) \
                    and isinstance(stmt.addr, ailment.Expr.StackBaseOffset) \
                    and isinstance(stmt.data, ailment.Expr.Load) \
                    and self._is_add(stmt.data.addr):
                # Check addr: must be fs+0x28
                op0, op1 = stmt.data.addr.operands
                if isinstance(op1, ailment.Expr.Register):
                    op0, op1 = op1, op0
                if isinstance(op0, ailment.Expr.Register) and isinstance(op1, ailment.Expr.Const):
                    if op0.reg_offset == self.project.arch.get_register_offset('fs') and op1.value == 0x28:
                        return first_block, idx

        return None

    def _find_canary_xor_stmt(self, block, canary_value_stack_offset):

        for idx, stmt in enumerate(block.statements):
            if isinstance(stmt, ailment.Stmt.ConditionalJump):
                if isinstance(stmt.condition, ailment.Expr.UnaryOp) and stmt.condition.op == "Not":
                    # !(s_10 ^ fs:0x28 == 0)
                    negated = True
                    condition = stmt.condition.operand
                else:
                    negated = False
                    condition = stmt.condition
                if isinstance(condition, ailment.Expr.BinaryOp) and (
                        not negated and condition.op == "CmpEQ" or
                        negated and condition.op == "CmpNE"
                ):
                   pass
                else:
                    continue

                expr = condition.operands[0]
                if not isinstance(expr, ailment.Expr.BinaryOp):
                    continue
                if expr.op != "Xor":
                    continue
                op0, op1 = expr.operands
                if not isinstance(op0, ailment.Expr.Load):
                    continue
                if not isinstance(op0.addr, ailment.Expr.StackBaseOffset):
                    continue
                bits = self.project.arch.bits
                if s2u(op0.addr.offset, bits) != s2u(canary_value_stack_offset, bits):
                    continue
                if not isinstance(op1, ailment.Expr.Load):
                    continue
                if not isinstance(op1.addr, ailment.Expr.BinaryOp):
                    continue
                if not op1.addr.op == "Add":
                    continue
                if not isinstance(op1.addr.operands[0], ailment.Expr.Const):
                    continue
                if op1.addr.operands[0].value != 0x28:
                    continue
                if not isinstance(op1.addr.operands[1], ailment.Expr.Register):
                    continue
                if op1.addr.operands[1].reg_offset != self.project.arch.get_register_offset('fs'):
                    continue

                # Found it
                return idx

        return None

    def _calls_stack_chk_fail(self, node):

        for stmt in node.statements:
            if isinstance(stmt, ailment.Stmt.Call) and isinstance(stmt.target, ailment.Expr.Const):
                const_target = stmt.target.value
                if const_target in self.kb.functions:
                    func = self.kb.functions.function(addr=const_target)
                    if func.name == "__stack_chk_fail":
                        return True

        return False


AnalysesHub.register_default("StackCanarySimplifier", StackCanarySimplifier)
