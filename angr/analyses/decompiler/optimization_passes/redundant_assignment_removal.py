# pylint:disable=unused-argument
from __future__ import annotations
from typing import TYPE_CHECKING
import logging

from angr.ailment import Block, AILBlockWalker, RemoveStatementNotice
from angr.ailment.expression import VirtualVariable
from angr.ailment.statement import Assignment

from angr.analyses.decompiler.ailgraph_walker import AILGraphWalker
from .optimization_pass import OptimizationPass, OptimizationPassStage

if TYPE_CHECKING:
    from angr import Project
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal


_l = logging.getLogger(name=__name__)


class BlockWalker(AILBlockWalker):
    def __init__(self, project: Project, varman: VariableManagerInternal):
        super().__init__(update_block=False)
        self._project = project
        self._varman = varman

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block):
        remove = False
        src = stmt.src
        dst = stmt.dst
        if (
            isinstance(src, VirtualVariable)
            and isinstance(dst, VirtualVariable)
            and src.variable is not None
            and dst.variable is not None
        ):
            if "struct_member_info" in src.tags and "struct_member_info" in dst.tags:
                if src.struct_member_info == dst.struct_member_info:
                    remove = True
            else:
                src_unified_var = self._varman.unified_variable(src.variable)
                dst_unified_var = self._varman.unified_variable(dst.variable)
                if src_unified_var is not None and dst_unified_var is not None and src_unified_var == dst_unified_var:
                    remove = True

        if remove:
            raise RemoveStatementNotice
        return None


class RedundantAssignmentRemoval(OptimizationPass):
    """
    Remove redundant assignments post-variable recovery. Due to how SSA works, we may have assignments that look like
    the following:

    vvar_1 (v4) = vvar_0 (v4);

    Both vvar_1 and vvar_0 are mapped to the same variable (v4) because vvar_1 is an inserted variable when
    transforming out of SSA. This optimization pass eliminates such redundant assignments.

    Note that once such redundant assignments are eliminated, this function is no longer suitable for analysis that
    expects SSA; specifically, there will be virtual variables that are used before being defined.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Remove redundant assignments created when transforming out of the SSA form"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self._block_walker = BlockWalker(
            self.project,
            (
                self._variable_kb.variables[self._func.addr]
                if self._variable_kb.variables.has_function_manager(self._func.addr)
                else None
            ),
        )
        self.analyze()

    def _check(self):
        return (True, None) if self._variable_kb is not None else (False, None)

    def _analyze(self, cache=None):
        # walk the entire graph and traverse each expression
        walker = AILGraphWalker(self._graph, handler=self._walk_block, replace_nodes=True)
        walker.walk()

    def _walk_block(self, block: Block) -> Block | None:
        return self._block_walker.walk(block)
