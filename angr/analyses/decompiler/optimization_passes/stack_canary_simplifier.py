# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
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
        if not (isinstance(canary_init_stmt.dst, ailment.Expr.VirtualVariable) and canary_init_stmt.dst.was_stack):
            _l.debug(
                "Unsupported canary storing location %s. Expects a stack VirtualVariable.",
                canary_init_stmt.addr,
            )
            return

        store_offset = canary_init_stmt.dst.stack_offset
        if not isinstance(store_offset, int):
            _l.debug("Unsupported canary storing offset %s. Expects an int.", store_offset)

        # The function should have at least one end point with an if-else statement
        # Find all nodes with 0 out-degrees
        all_endpoint_addrs = [node.addr for node in self._func.graph.nodes() if self._func.graph.out_degree(node) == 0]

        # Before node duplication, each pair of canary-check-success and canary-check-failure nodes have a common
        # predecessor.
        # map endpoint addrs to their common predecessors
        pred_addr_to_endpoint_addrs: dict[int, set[int]] = defaultdict(set)
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
                ret_node = succs[1] if stack_chk_fail_caller is succs[0] else succs[0]
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
        block_addr = self._func.addr
        traversed = set()

        while True:
            traversed.add(block_addr)
            try:
                first_block = next(self._get_blocks(block_addr))
            except StopIteration:
                break

            if first_block is None:
                break

            for idx, stmt in enumerate(first_block.statements):
                if (
                    isinstance(stmt, ailment.Stmt.Assignment)
                    and isinstance(stmt.dst, ailment.Expr.VirtualVariable)
                    and stmt.dst.was_stack
                    and isinstance(stmt.dst.stack_offset, int)
                    and isinstance(stmt.src, ailment.Expr.Load)
                    and self._is_add(stmt.src.addr)
                ):
                    # Check addr: must be fs+0x28
                    op0, op1 = stmt.src.addr.operands
                    if isinstance(op1, ailment.Expr.VirtualVariable) and op1.was_reg:
                        op0, op1 = op1, op0
                    if (
                        isinstance(op0, ailment.Expr.VirtualVariable)
                        and op0.was_reg
                        and isinstance(op1, ailment.Expr.Const)
                        and op0.reg_offset == self.project.arch.get_register_offset("fs")
                        and op1.value == 0x28
                    ):
                        return first_block, idx

            succs = list(self._graph.successors(first_block))
            if len(succs) == 1:
                block_addr = succs[0].addr
                if block_addr not in traversed:
                    continue
            break

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
                    if isinstance(op0, ailment.Expr.VirtualVariable) and op0.was_reg:
                        # maybe op0 holds the value of another stack variable, like the following:
                        #
                        # 00 | 0x404e75 | LABEL_404e75:
                        # 01 | 0x404e75 | vvar_62{reg 16} = vvar_79{stack -64}
                        # 02 | 0x404e7a | vvar_66{reg 16} = (vvar_62{reg 16} ^ Load(addr=(0x28<64> + vvar_31{reg 208}),
                        #                 size=8, endness=Iend_LE))
                        # 03 | 0x404e83 | if (((vvar_62{reg 16} ^ Load(addr=(0x28<64> + vvar_31{reg 208}), size=8,
                        #                 endness=Iend_LE)) == 0x0<64>)) { Goto ... } else { Goto ... }
                        op0_v = self._get_vvar_value(block, op0.varid)
                        if isinstance(op0_v, ailment.Expr.VirtualVariable) and op0_v.was_stack:
                            op0 = op0_v

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
        if not (
            isinstance(expr, ailment.Expr.VirtualVariable) and expr.was_stack and isinstance(expr.stack_offset, int)
        ):
            return False
        return s2u(expr.stack_offset, bits) == s2u(canary_value_stack_offset, bits)

    @staticmethod
    def _is_random_number_load_expr(expr, fs_reg_offset: int) -> bool:
        return (
            isinstance(expr, ailment.Expr.Load)
            and isinstance(expr.addr, ailment.Expr.BinaryOp)
            and expr.addr.op == "Add"
            and isinstance(expr.addr.operands[0], ailment.Expr.Const)
            and expr.addr.operands[0].value == 0x28
            and isinstance(expr.addr.operands[1], ailment.Expr.VirtualVariable)
            and expr.addr.operands[1].was_reg
            and expr.addr.operands[1].reg_offset == fs_reg_offset
        )

    @staticmethod
    def _get_vvar_value(block: ailment.Block, vvar_id: int) -> ailment.Expression | None:
        for stmt in block.statements:
            if (
                isinstance(stmt, ailment.Stmt.Assignment)
                and isinstance(stmt.dst, ailment.Expr.VirtualVariable)
                and stmt.dst.varid == vvar_id
            ):
                return stmt.src
        return None
