from typing import Set, Dict
from collections import defaultdict
import logging

import ailment

from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(name=__name__)


def s2u(s, bits):
    if s > 0:
        return s
    return (1 << bits) + s


class StackCanarySimplifier(OptimizationPass):
    """
    Removes stack canary checks from decompilation results.
    """

    ARCHES = [
        "X86",
        "AMD64",
    ]  # TODO: fs is x86 only. Figure out how stack canary is loaded in other architectures
    PLATFORMS = ["cgc", "linux"]
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify stack canaries"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.analyze()

    def _check(self):
        # Check the first block and see if there is any statement reading data from fs:0x28h
        init_stmt = self._find_canary_init_stmt()

        return init_stmt is not None, {"init_stmt": init_stmt}

    def _analyze(self, cache=None):
        init_stmt = None
        if cache is not None:
            init_stmt = cache.get("init_stmt", None)

        if init_stmt is None:
            init_stmt = self._find_canary_init_stmt()

        if init_stmt is None:
            return

        # Look for the statement that loads back canary value from the stack
        first_block, stmt_idx = init_stmt
        canary_init_stmt = first_block.statements[stmt_idx]
        # where is the stack canary stored?
        if not isinstance(canary_init_stmt.addr, ailment.Expr.StackBaseOffset):
            _l.debug(
                "Unsupported canary storing location %s. Expects an ailment.Expr.StackBaseOffset.",
                canary_init_stmt.addr,
            )
            return

        store_offset = canary_init_stmt.addr.offset
        if not isinstance(store_offset, int):
            _l.debug("Unsupported canary storing offset %s. Expects an int.", store_offset)

        # The function should have at least one end point with an if-else statement
        # Find all nodes with 0 out-degrees
        all_endpoint_addrs = [node.addr for node in self._func.graph.nodes() if self._func.graph.out_degree(node) == 0]

        # Before node duplication, each pair of canary-check-success and canary-check-failure nodes have a common
        # predecessor.
        # map endpoint addrs to their common predecessors
        pred_addr_to_endpoint_addrs: Dict[int, Set[int]] = defaultdict(set)
        for node_addr in all_endpoint_addrs:
            preds = self._func.graph.predecessors(self._func.get_node(node_addr))
            for pred in preds:
                pred_addr_to_endpoint_addrs[pred.addr].add(node_addr)

        found_endpoints = False
        for pred_addr in pred_addr_to_endpoint_addrs:
            endpoint_addrs = pred_addr_to_endpoint_addrs[pred_addr]

            if len(endpoint_addrs) != 2:
                # we expect there to be only two nodes: one for canary-check-success, and the other for
                # canary-check-failure. if not, we check the next predecessor
                continue

            # because other optimization passes may duplicate nodes, we may have more than one node for each function
            # endpoint.
            endpoint_addrs_list = list(endpoint_addrs)
            endnodes_0 = list(self._get_blocks(endpoint_addrs_list[0]))
            endnodes_1 = list(self._get_blocks(endpoint_addrs_list[1]))

            if not endnodes_0 or not endnodes_1:
                _l.warning("Unexpected situation: endnodes_0 or endnodes_1 is empty.")
                continue

            # One of the end nodes calls __stack_chk_fail
            stack_chk_fail_callers = None
            other_nodes = None
            for endnodes, o in [(endnodes_0, endnodes_1), (endnodes_1, endnodes_0)]:
                if self._calls_stack_chk_fail(endnodes[0]):
                    stack_chk_fail_callers = endnodes
                    other_nodes = o
                    break
            else:
                _l.debug("Cannot find the node that calls __stack_chk_fail().")
                continue

            # Match stack_chk_fail_caller, ret_node, and predecessor
            nodes_to_process = []
            for stack_chk_fail_caller in stack_chk_fail_callers:
                all_preds = set(self._graph.predecessors(stack_chk_fail_caller))
                preds_for_other_nodes = set()
                for o in other_nodes:
                    preds_for_other_nodes |= set(self._graph.predecessors(o))
                preds = list(all_preds.intersection(preds_for_other_nodes))
                if len(preds) != 1:
                    _l.debug("Expect 1 predecessor. Found %d.", len(preds))
                    continue
                pred = preds[0]

                # More sanity checks
                if len(pred.statements) < 1:
                    _l.debug("The predecessor node is empty.")
                    continue

                # Check the last statement
                if not isinstance(pred.statements[-1], ailment.Stmt.ConditionalJump):
                    _l.debug("The predecessor does not end with a conditional jump.")
                    continue

                # Find the statement that computes real canary value xor stored canary value
                canary_check_stmt_idx = self._find_canary_comparison_stmt(pred, store_offset)
                if canary_check_stmt_idx is None:
                    _l.debug("Cannot find the canary check statement in the predecessor.")
                    continue

                succs = list(self._graph.successors(pred))
                if len(succs) != 2:
                    _l.debug("Expect 2 successors. Found %d.", len(succs))
                    continue
                if stack_chk_fail_caller is succs[0]:
                    ret_node = succs[1]
                else:
                    ret_node = succs[0]
                nodes_to_process.append((pred, canary_check_stmt_idx, stack_chk_fail_caller, ret_node))

            # Awesome. Now patch this function.
            for pred, canary_check_stmt_idx, stack_chk_fail_caller, ret_node in nodes_to_process:
                # Patch the pred so that it jumps to the one that is not stack_chk_fail_caller
                pred_copy = pred.copy()
                pred_copy.statements[-1] = ailment.Stmt.Jump(
                    len(pred_copy.statements) - 1,
                    ailment.Expr.Const(None, None, ret_node.addr, self.project.arch.bits),
                    ins_addr=pred_copy.statements[-1].ins_addr,
                )

                self._graph.remove_edge(pred, stack_chk_fail_caller)
                self._update_block(pred, pred_copy)

                if self._graph.in_degree[stack_chk_fail_caller] == 0:
                    # Remove the block that calls stack_chk_fail_caller
                    self._remove_block(stack_chk_fail_caller)

                found_endpoints = True

        if found_endpoints:
            # Remove the statement that loads the stack canary from fs
            first_block_copy = first_block.copy()
            first_block_copy.statements.pop(stmt_idx)
            self._update_block(first_block, first_block_copy)

        # Done!

    def _find_canary_init_stmt(self):
        first_block = self._get_block(self._func.addr)
        if first_block is None:
            return None

        for idx, stmt in enumerate(first_block.statements):
            if (
                isinstance(stmt, ailment.Stmt.Store)
                and isinstance(stmt.addr, ailment.Expr.StackBaseOffset)
                and isinstance(stmt.data, ailment.Expr.Load)
                and self._is_add(stmt.data.addr)
            ):
                # Check addr: must be fs+0x28
                op0, op1 = stmt.data.addr.operands
                if isinstance(op1, ailment.Expr.Register):
                    op0, op1 = op1, op0
                if isinstance(op0, ailment.Expr.Register) and isinstance(op1, ailment.Expr.Const):
                    if op0.reg_offset == self.project.arch.get_register_offset("fs") and op1.value == 0x28:
                        return first_block, idx

        return None

    def _find_canary_comparison_stmt(self, block, canary_value_stack_offset):
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
                    not negated and condition.op == "CmpEQ" or negated and condition.op == "CmpNE"
                ):
                    pass
                else:
                    continue

                expr0, expr1 = condition.operands
                if isinstance(expr0, ailment.Expr.BinaryOp) and expr0.op == "Xor":
                    # a ^ b
                    op0, op1 = expr0.operands
                    if not (
                        self._is_stack_canary_load_expr(op0, self.project.arch.bits, canary_value_stack_offset)
                        and self._is_random_number_load_expr(op1, self.project.arch.get_register_offset("fs"))
                        or (
                            self._is_stack_canary_load_expr(op1, self.project.arch.bits, canary_value_stack_offset)
                            and self._is_random_number_load_expr(op0, self.project.arch.get_register_offset("fs"))
                        )
                    ):
                        continue
                elif (
                    isinstance(expr0, ailment.Expr.Load)
                    and isinstance(expr1, ailment.Expr.Load)
                    and condition.op == "CmpEQ"
                ):
                    # a == b
                    if not (
                        self._is_stack_canary_load_expr(expr0, self.project.arch.bits, canary_value_stack_offset)
                        and self._is_random_number_load_expr(expr1, self.project.arch.get_register_offset("fs"))
                        or (
                            self._is_stack_canary_load_expr(expr1, self.project.arch.bits, canary_value_stack_offset)
                            and self._is_random_number_load_expr(expr0, self.project.arch.get_register_offset("fs"))
                        )
                    ):
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

    @staticmethod
    def _is_stack_canary_load_expr(expr, bits: int, canary_value_stack_offset: int) -> bool:
        if not (isinstance(expr, ailment.Expr.Load) and isinstance(expr.addr, ailment.Expr.StackBaseOffset)):
            return False
        if s2u(expr.addr.offset, bits) != s2u(canary_value_stack_offset, bits):
            return False
        return True

    @staticmethod
    def _is_random_number_load_expr(expr, fs_reg_offset: int) -> bool:
        return (
            isinstance(expr, ailment.Expr.Load)
            and isinstance(expr.addr, ailment.Expr.BinaryOp)
            and expr.addr.op == "Add"
            and isinstance(expr.addr.operands[0], ailment.Expr.Const)
            and expr.addr.operands[0].value == 0x28
            and isinstance(expr.addr.operands[1], ailment.Expr.Register)
            and expr.addr.operands[1].reg_offset == fs_reg_offset
        )
