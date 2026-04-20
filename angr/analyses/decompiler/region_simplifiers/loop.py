# pylint:disable=unused-argument,arguments-differ
from __future__ import annotations
from collections import defaultdict

import angr.ailment as ailment

from angr.analyses.decompiler.condition_processor import ConditionProcessor, EmptyBlockNotice
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structuring.structurer_nodes import (
    SequenceNode,
    CodeNode,
    MultiNode,
    LoopNode,
    ConditionNode,
    ContinueNode,
    CascadingConditionNode,
)
from angr.analyses.decompiler.utils import is_statement_terminating, has_nonlabel_nonphi_statements
from angr.utils.ail import is_phi_assignment


class LoopSimplifier(SequenceWalker):
    """
    Simplifies loops.
    """

    def __init__(self, node, functions):
        handlers = {
            SequenceNode: self._handle_sequencenode,
            CodeNode: self._handle_codenode,
            MultiNode: self._handle_multinode,
            LoopNode: self._handle_loopnode,
            ConditionNode: self._handle_conditionnode,
            CascadingConditionNode: self._handle_cascadingconditionnode,
            ailment.Block: self._handle_block,
        }

        super().__init__(handlers)
        self.functions = functions
        self.continue_preludes: dict[LoopNode, list[ailment.Block]] = defaultdict(list)
        self.walk(node)

    @staticmethod
    def _control_transferring_statement(stmt: ailment.Stmt.Statement) -> bool:
        return isinstance(
            stmt,
            (ailment.Stmt.SideEffectStatement, ailment.Stmt.Return, ailment.Stmt.Jump, ailment.Stmt.ConditionalJump),
        )

    def _handle_sequencenode(self, node, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):
        for n0, n1, n2 in zip(node.nodes, [*node.nodes[1:], successor], [predecessor, *node.nodes[:-1]]):
            self._handle(n0, predecessor=n2, successor=n1, loop=loop, loop_successor=loop_successor)

    def _handle_codenode(self, node, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):
        self._handle(node.node, predecessor=predecessor, successor=successor, loop=loop, loop_successor=loop_successor)

    def _handle_conditionnode(self, node, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):
        if node.true_node is not None:
            self._handle(
                node.true_node, predecessor=predecessor, successor=successor, loop=loop, loop_successor=loop_successor
            )
        if node.false_node is not None:
            self._handle(
                node.false_node, predecessor=predecessor, successor=successor, loop=loop, loop_successor=loop_successor
            )

    def _handle_cascadingconditionnode(
        self, node: CascadingConditionNode, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs
    ):
        for _, child_node in node.condition_and_nodes:
            self._handle(
                child_node, predecessor=predecessor, successor=successor, loop=loop, loop_successor=loop_successor
            )
        if node.else_node is not None:
            self._handle(
                node.else_node, predecessor=predecessor, successor=successor, loop=loop, loop_successor=loop_successor
            )

    def _handle_loopnode(
        self, node: LoopNode, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs
    ):
        self._handle(
            node.sequence_node, predecessor=predecessor, successor=successor, loop=node, loop_successor=successor
        )

        # find for-loop iterators
        if (
            (
                node.sort == "while"
                and self.continue_preludes[node]
                and (
                    (node.condition is not None and not isinstance(node.condition, ailment.Expr.Const))
                    or len(self.continue_preludes[node]) > 1
                )
            )
            and (
                all(block.statements for block in self.continue_preludes[node])
                and all(
                    not self._control_transferring_statement(block.statements[-1])
                    for block in self.continue_preludes[node]
                )
                and all(
                    block.statements[-1] == self.continue_preludes[node][0].statements[-1]
                    for block in self.continue_preludes[node]
                )
            )
            and (
                all(has_nonlabel_nonphi_statements(block) for block in self.continue_preludes[node])
                and all(not is_phi_assignment(block.statements[-1]) for block in self.continue_preludes[node])
            )
        ):
            node.sort = "for"
            node.iterator = self.continue_preludes[node][0].statements[-1]
            for block in self.continue_preludes[node]:
                block.statements = block.statements[:-1]

        # Fix do-while condition off-by-one: when VEX tests the pre-modification
        # value (e.g., CmpEQ(eax_old, 1) for sub eax,1; jne), the do-while body
        # has already modified the variable, so the comparison constant must be
        # adjusted.  Pattern:
        #   do { ...; v1 -= C; } while (v1 != K)  =>  while (v1 != K - C)
        if node.sort == "do-while" and node.condition is not None:
            node.condition = self._adjust_dowhile_condition(node)

        # find for-loop initializers
        if isinstance(predecessor, MultiNode):
            predecessor = predecessor.nodes[-1]
        if (
            node.sort == "for"
            and isinstance(predecessor, ailment.Block)
            and predecessor.statements
            and isinstance(predecessor.statements[-1], (ailment.Stmt.Assignment, ailment.Stmt.Store))
        ):
            node.initializer = predecessor.statements[-1]
            predecessor.statements = predecessor.statements[:-1]

    @staticmethod
    def _adjust_dowhile_condition(node: LoopNode):
        """
        When a do-while condition tests a phi variable that is modified in the
        loop body, the comparison constant needs adjustment because the condition
        is evaluated after the modification.

        Example: ``do { ...; flag -= 1; } while (flag != 1)`` should become
        ``while (flag != 0)`` because the x86 ``sub eax,1; jne`` tests the
        *result*, but VEX compares the pre-decrement value.
        """
        cond = node.condition
        if not (isinstance(cond, ailment.Expr.BinaryOp) and cond.op in ("CmpNE", "CmpEQ")):
            return cond

        cond_var, cond_const = cond.operands
        if isinstance(cond_const, ailment.Expr.VirtualVariable) and isinstance(cond_var, ailment.Expr.Const):
            cond_var, cond_const = cond_const, cond_var
        if not (isinstance(cond_var, ailment.Expr.VirtualVariable) and isinstance(cond_const, ailment.Expr.Const)):
            return cond

        # Find the assignment to this phi variable's back-edge definition in the body.
        # Pattern: body has  phi_var = phi(back_def, init)  and  back_def = phi_var - C
        phi_stmt = None
        mod_stmt = None

        def _scan_body(n):
            nonlocal phi_stmt, mod_stmt
            if isinstance(n, ailment.Block):
                for s in n.statements:
                    if (
                        isinstance(s, ailment.Stmt.Assignment)
                        and isinstance(s.dst, ailment.Expr.VirtualVariable)
                        and s.dst.varid == cond_var.varid
                        and isinstance(s.src, ailment.Expr.Phi)
                    ):
                        phi_stmt = s
                    if (
                        isinstance(s, ailment.Stmt.Assignment)
                        and isinstance(s.dst, ailment.Expr.VirtualVariable)
                        and isinstance(s.src, ailment.Expr.BinaryOp)
                        and s.src.op in ("Sub", "Add")
                        and isinstance(s.src.operands[0], ailment.Expr.VirtualVariable)
                        and s.src.operands[0].varid == cond_var.varid
                        and isinstance(s.src.operands[1], ailment.Expr.Const)
                    ):
                        mod_stmt = s
            for attr in ("nodes", "node"):
                child = getattr(n, attr, None)
                if child is not None:
                    for c in child if isinstance(child, list) else [child]:
                        _scan_body(c)

        _scan_body(node.sequence_node)

        if phi_stmt is None or mod_stmt is None:
            return cond

        # Verify the modifier's destination feeds back into the phi
        mod_dst_varid = mod_stmt.dst.varid
        feeds_phi = any(
            isinstance(src, ailment.Expr.VirtualVariable) and src.varid == mod_dst_varid
            for _, src in phi_stmt.src.src_and_vvars
        )
        if not feeds_phi:
            return cond

        # Adjust the comparison constant
        mod_const = mod_stmt.src.operands[1].value
        old_k = cond_const.value
        if mod_stmt.src.op == "Sub":
            new_k = (old_k - mod_const) & ((1 << cond_const.bits) - 1)
        else:
            new_k = (old_k + mod_const) & ((1 << cond_const.bits) - 1)

        if new_k == old_k:
            return cond

        # Also update the condition to reference the post-modification variable
        new_const = ailment.Expr.Const(cond_const.idx, None, new_k, cond_const.bits, **cond_const.tags)
        new_var = mod_stmt.dst
        return ailment.Expr.BinaryOp(cond.idx, cond.op, [new_var, new_const], cond.signed, **cond.tags)

    def _handle_multinode(self, node, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):
        for n0, n1, n2 in zip(node.nodes, [*node.nodes[1:], successor], [predecessor, *node.nodes[:-1]]):
            self._handle(n0, predecessor=n2, successor=n1, loop=loop, loop_successor=loop_successor)

    def _handle_block(self, block, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):  # pylint:disable=no-self-use
        if isinstance(successor, ContinueNode) or successor is loop_successor:
            # ensure this block is not returning or exiting
            try:
                last_stmt = ConditionProcessor.get_last_statement(block)
            except EmptyBlockNotice:
                last_stmt = None
            if last_stmt is not None and is_statement_terminating(last_stmt, self.functions):
                return
            self.continue_preludes[loop].append(block)
