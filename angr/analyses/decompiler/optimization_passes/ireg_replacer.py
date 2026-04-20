from __future__ import annotations
import logging

from angr.ailment.statement import Assignment
from angr.ailment.expression import IRegister, Register

from .engine_base import SimplifierAILEngine, SimplifierAILState
from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class IRegReplacerEngine(SimplifierAILEngine):
    def __init__(self, project, ail_manager=None):
        super().__init__(project)
        self._ail_manager = ail_manager
        self._max_reg_offset = max(off + sz for _, (off, sz) in project.arch.registers.items())

    def _next_atom(self):
        return self._ail_manager.next_atom() if self._ail_manager else None

    def _try_resolve(self, ireg: IRegister) -> Register | None:
        offset = ireg.concrete_reg_offset()
        if offset is not None and 0 <= offset < self._max_reg_offset:
            return Register(self._next_atom() or ireg.idx, None, offset, ireg.bits, **ireg.tags)
        return None

    def _handle_stmt_Assignment(self, stmt: Assignment) -> Assignment | None:
        if isinstance(stmt.dst, IRegister):
            resolved = self._try_resolve(stmt.dst)
            if resolved is not None:
                new_src = self._expr(stmt.src)
                return Assignment(stmt.idx, resolved, new_src if new_src is not None else stmt.src, **stmt.tags)
        return super()._handle_stmt_Assignment(stmt)

    def _handle_expr_IRegister(self, expr: IRegister) -> Register | IRegister:
        resolved = self._try_resolve(expr)
        return resolved if resolved is not None else expr


class IRegReplacer(OptimizationPass):
    """
    Replaces IRegister expressions (from GetI/PutI) with concrete Register
    expressions when the index has been resolved to a constant.
    """

    ARCHES = [
        "X86",
        "AMD64",
        "ARMCortexM",
        "ARMHF",
        "ARMEL",
    ]
    PLATFORMS = ["linux", "windows"]
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Resolve IRegister to Register"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, *args, **kwargs):
        super().__init__(func, *args, **kwargs)

        self.state = SimplifierAILState(self.project.arch)
        self.engine = IRegReplacerEngine(self.project, ail_manager=self.manager)

        self.analyze()

    def _check(self):
        if self._graph is not None:
            for block in self._graph.nodes():
                for stmt in block.statements:
                    if isinstance(stmt, Assignment) and isinstance(stmt.dst, IRegister):
                        return True, None
                    if self._has_ireg(stmt):
                        return True, None
        return False, None

    @staticmethod
    def _has_ireg(stmt) -> bool:
        worklist = []
        if hasattr(stmt, "src"):
            worklist.append(stmt.src)
        if hasattr(stmt, "data"):
            worklist.append(stmt.data)
        if hasattr(stmt, "condition"):
            worklist.append(stmt.condition)
        while worklist:
            expr = worklist.pop()
            if isinstance(expr, IRegister):
                return True
            if hasattr(expr, "operands"):
                worklist.extend(expr.operands)
        return False

    def _analyze(self, cache=None):
        assert self._graph is not None
        for block in list(self._graph.nodes()):
            new_block = block
            old_block = None

            while new_block != old_block:
                old_block = new_block
                new_block = self.engine.process(state=self.state.copy(), block=old_block.copy())
                _l.debug("new block: %s", new_block.statements)

            # Remove any remaining unresolved IRegister assignments (x87
            # bookkeeping like fptag writes that couldn't be resolved due to
            # cross-block ftop dependencies).
            cleaned = [
                s for s in new_block.statements if not (isinstance(s, Assignment) and isinstance(s.dst, IRegister))
            ]
            if len(cleaned) != len(new_block.statements):
                new_block = new_block.copy(statements=cleaned)

            self._update_block(block, new_block)
