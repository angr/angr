# pylint:disable=unused-argument
from __future__ import annotations
from typing import TYPE_CHECKING
import logging

from angr.ailment import Block, AILBlockRewriter
from angr.ailment.expression import Load, Const
from angr.ailment.statement import Statement

from angr.analyses.decompiler.ailgraph_walker import AILGraphWalker
from .optimization_pass import OptimizationPass, OptimizationPassStage

if TYPE_CHECKING:
    from angr import Project


_l = logging.getLogger(name=__name__)


class BlockWalker(AILBlockRewriter):
    """
    AIL Block walker in order to perform const deref substitution
    """

    def __init__(self, project: Project):
        super().__init__()
        self._project = project
        self._new_block: Block | None = None  # output

    def _addr_belongs_to_ro_region(self, addr: int) -> bool:
        section = self._project.loader.find_section_containing(addr)
        if section is not None:
            return not section.is_writable
        segment = self._project.loader.find_segment_containing(addr)
        if segment is not None:
            return not segment.is_writable
        return False

    def _addr_belongs_to_got(self, addr: int) -> bool:
        section = self._project.loader.find_section_containing(addr)
        if section is not None:
            return section.name and "got" in section.name
        return False

    def _addr_belongs_to_object(self, addr: int) -> bool:
        obj = self._project.loader.find_object_containing(addr)
        return obj is not None

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block):
        if isinstance(expr.addr, Const):
            assert isinstance(expr.addr.value, int)
            # *(const_addr)
            # does it belong to a read-only section/segment?
            is_got = self._addr_belongs_to_got(expr.addr.value)
            if is_got or self._addr_belongs_to_ro_region(expr.addr.value):
                try:
                    w = self._project.loader.memory.unpack_word(
                        expr.addr.value,
                        expr.addr.bits // self._project.arch.byte_width,
                        endness=self._project.arch.memory_endness,
                    )
                except KeyError:
                    # we don't have enough bytes to read out
                    w = None
                if w is not None and not (is_got and w == 0):
                    # nice! replace it with the actual value
                    return Const(None, None, w, expr.bits, **expr.tags)
        elif (
            isinstance(expr.addr, Load)
            and expr.addr.bits == self._project.arch.bits
            and isinstance(expr.addr.addr, Const)
        ):
            assert isinstance(expr.addr.addr.value, int)
            # *(*(const_addr))
            # does it belong to a read-only section/segment?
            if self._addr_belongs_to_got(expr.addr.addr.value) or self._addr_belongs_to_ro_region(expr.addr.addr.value):
                w = self._project.loader.memory.unpack_word(
                    expr.addr.addr.value,
                    expr.addr.addr.bits // self._project.arch.byte_width,
                    endness=self._project.arch.memory_endness,
                )
                if w is not None and self._addr_belongs_to_object(w):
                    # nice! replace it with a load from that address
                    return Load(
                        expr.idx,
                        Const(None, None, w, expr.addr.size, **expr.addr.addr.tags),
                        expr.size,
                        expr.endness,
                        variable=expr.variable,
                        variable_offset=expr.variable_offset,
                        guard=expr.guard,
                        alt=expr.alt,
                        **expr.tags,
                    )

        return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)


class ConstantDereferencesSimplifier(OptimizationPass):
    """
    Makes the following simplifications::

        *(*(const_addr))  ==>  *(value) iff  *const_addr == value
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_SINGLE_BLOCK_SIMPLIFICATION
    NAME = "Simplify constant dereferences"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self._block_walker = BlockWalker(self.project)
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        # walk the entire graph and traverse each expression
        walker = AILGraphWalker(self._graph, handler=self._walk_block, replace_nodes=True)
        walker.walk()

    def _walk_block(self, block: Block) -> Block | None:
        return self._block_walker.walk(block)
