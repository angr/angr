from __future__ import annotations
from collections import defaultdict
import logging
from typing import Any

from ailment.block import Block
from ailment.statement import Assignment
from ailment.expression import VirtualVariable, Phi

from angr.utils.ail import is_phi_assignment
from angr.knowledge_plugins.functions import Function
from angr.analyses import register_analysis
from angr.analyses.decompiler.structuring.structurer_nodes import SequenceNode
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from .dephication_base import DephicationBase
from .rewriting_engine import SimEngineDephiRewriting


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

    def __init__(self, seq_node: SequenceNode, vvar_to_vvar: dict[int, int], arch):
        super().__init__(
            handlers={
                Block: self._handle_Block,
            }
        )

        self.vvar_to_vvar = vvar_to_vvar
        self.engine = SimEngineDephiRewriting(arch, self.vvar_to_vvar)

        self.output = self.walk(seq_node)
        if self.output is None:
            # nothing is changed during rewriting
            self.output = seq_node

    def _handle_Block(self, block: Block, **kwargs) -> Block | None:  # pylint:disable=unused-argument
        self.engine.out_block = None
        self.engine.process(None, block=block)
        if self.engine.out_block is not None:
            out = self.engine.out_block
            out.statements = [stmt for stmt in out.statements if not is_phi_assignment(stmt)]
            self.engine.out_block = None
            return out
        return None


class SeqNodeDephication(DephicationBase):
    """
    SeqNodeDephication removes phi expressions from an AIL SeqNode and its children.
    """

    def __init__(
        self, func: Function | str, seq_node, vvar_to_vvar_mapping: dict[int, int] | None = None, rewrite: bool = False
    ):
        super().__init__(func, vvar_to_vvar_mapping=vvar_to_vvar_mapping, rewrite=rewrite)

        self._seq_node = seq_node

        self._analyze()

    def _collect_phi_assignments(self) -> dict[int, set[int]]:
        # traverse children of the SequenceNode object and find all phi assignment statements
        collector = PhiAssignmentCollector(self._seq_node)
        return collector.phi_to_src

    def _rewrite_container(self) -> Any:
        rewriter = SeqNodeRewriter(self._seq_node, self.vvar_to_vvar_mapping, self.project.arch)
        return rewriter.output


register_analysis(SeqNodeDephication, "SeqNodeDephication")
