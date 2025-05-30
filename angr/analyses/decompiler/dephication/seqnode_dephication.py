from __future__ import annotations
from collections import defaultdict
import logging
from typing import Any, TYPE_CHECKING

from angr.ailment.block import Block
from angr.ailment.statement import Assignment
from angr.ailment.expression import VirtualVariable, Phi, BinaryOp, UnaryOp

import angr
from angr.utils.ail import is_phi_assignment
from angr.knowledge_plugins.functions import Function
from angr.analyses import register_analysis
from angr.analyses.decompiler.structuring.structurer_nodes import SequenceNode, LoopNode
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from .dephication_base import DephicationBase
from .rewriting_engine import SimEngineDephiRewriting

if TYPE_CHECKING:
    from angr import KnowledgeBase


l = logging.getLogger(__name__)


class PhiAssignmentCollector(SequenceWalker):
    """
    PhiAssignmentCollector collects all phi variables and their corresponding source virtual variables in a
    SequenceNode.
    """

    def __init__(self, seq_node: SequenceNode):
        super().__init__(
            handlers={
                Block: self._handle_Block,
            }
        )

        self.phi_to_src: dict[int, set[int]] = defaultdict(set)

        self.walk(seq_node)

    def _handle_Block(self, block: Block, **kwargs) -> None:  # pylint:disable=unused-argument

        for stmt in block.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi):
                for _, vvar in stmt.src.src_and_vvars:
                    if vvar is None:
                        l.debug("Invalid vvar None found in %r.src.src_and_vvars.", stmt)
                    else:
                        self.phi_to_src[stmt.dst.varid].add(vvar.varid)


class SeqNodeRewriter(SequenceWalker):
    """
    SeqNodeRewriter rewrites a SequenceNode by replacing all phi variables with their corresponding source virtual
    variables.
    """

    def __init__(
        self,
        seq_node: SequenceNode,
        vvar_to_vvar: dict[int, int],
        project: angr.Project,
        variable_kb: KnowledgeBase | None = None,
        func_addr: int | None = None,
    ):
        super().__init__(
            handlers={
                Block: self._handle_Block,
                # statement handlers
                Assignment: self._handle_Assignment,
                # expression handlers
                BinaryOp: self._handle_BinaryOp,
                UnaryOp: self._handle_UnaryOp,
            }
        )

        self.vvar_to_vvar = vvar_to_vvar
        self.engine = SimEngineDephiRewriting(project, self.vvar_to_vvar, func_addr=func_addr, variable_kb=variable_kb)

        self.output = self.walk(seq_node)
        if self.output is None:
            # nothing is changed during rewriting
            self.output = seq_node

    def _handle_Assignment(self, stmt: Assignment, **kwargs) -> Assignment:  # pylint:disable=unused-argument
        return self.engine._handle_stmt_Assignment(stmt)

    def _handle_BinaryOp(self, expr, **kwargs):  # pylint:disable=unused-argument
        return self.engine._handle_expr_BinaryOp(expr)

    def _handle_UnaryOp(self, expr, **kwargs):  # pylint:disable=unused-argument
        return self.engine._handle_expr_UnaryOp(expr)

    def _handle_Block(self, block: Block, **kwargs) -> Block | None:  # pylint:disable=unused-argument
        self.engine.out_block = None
        self.engine.process(None, block=block)
        if self.engine.out_block is not None:
            out = self.engine.out_block
            out.statements = [stmt for stmt in out.statements if not is_phi_assignment(stmt)]
            self.engine.out_block = None
            return out
        return None

    def _handle_Loop(self, node: LoopNode, **kwargs):
        new_loop = super()._handle_Loop(node, **kwargs)
        changed = False
        if new_loop is None:
            new_loop = node
        else:
            changed = True

        if is_phi_assignment(new_loop.initializer):
            changed = True
            new_loop.initializer = None
        return new_loop if changed else None


class SeqNodeDephication(DephicationBase):
    """
    SeqNodeDephication removes phi expressions from a SequenceNode and its children. It also removes redundant variable
    assignments, e.g., `vvar_2 = vvar_1` where both vvar_1 and vvar_2 are mapped to the same variable.
    """

    def __init__(
        self,
        func: Function | str,
        seq_node,
        vvar_to_vvar_mapping: dict[int, int] | None = None,
        rewrite: bool = False,
        variable_kb: KnowledgeBase | None = None,
    ):
        super().__init__(func, vvar_to_vvar_mapping=vvar_to_vvar_mapping, rewrite=rewrite, variable_kb=variable_kb)

        self._seq_node = seq_node

        self._analyze()

    def _collect_phi_assignments(self) -> dict[int, set[int]]:
        # traverse children of the SequenceNode object and find all phi assignment statements
        collector = PhiAssignmentCollector(self._seq_node)
        return collector.phi_to_src

    def _rewrite_container(self) -> Any:
        rewriter = SeqNodeRewriter(
            self._seq_node,
            self.vvar_to_vvar_mapping,
            self.project,
            func_addr=self._function.addr,
            variable_kb=self.variable_kb,
        )
        return rewriter.output


register_analysis(SeqNodeDephication, "SeqNodeDephication")
