import logging

import ailment

from ... import AnalysesHub
from .optimization_pass import OptimizationPass

_l = logging.getLogger(name=__name__)


class BasePointerSaveSimplifier(OptimizationPass):

    ARCHES = ['X86', 'AMD64', 'ARMEL']
    PLATFORMS = ['linux']

    def __init__(self, func, blocks):
        super().__init__(func, blocks)
        self.analyze()

    def _check(self):
        save_stmt = self._find_retaddr_save_stmt()

        return save_stmt is not None, {'save_stmt': save_stmt}

    def _analyze(self, cache=None):
        save_stmt = None
        if cache is not None:
            save_stmt = cache.get('save_stmt', None)

        if save_stmt is None:
            save_stmt = self._find_retaddr_save_stmt()

        if save_stmt is None:
            return

        block, stmt_idx = save_stmt

        bmap = {}
        for addr, size in self._blocks:
            b = self._get_block(addr, size)
            if b is None:
                continue
            b_copy = b.copy()
            for idx, stmt in reversed(list(enumerate(b.statements))):
                if isinstance(stmt, ailment.Stmt.Assignment) \
                        and stmt.dst == block.statements[stmt_idx].data:
                    b_copy.statements.pop(idx)
            bmap[b] = b_copy
        for b, b_copy in bmap.items():
            self._update_block(b, b_copy)

        block_copy = block.copy()
        block_copy.statements.pop(stmt_idx)
        self._update_block(block, block_copy)

    def _find_retaddr_save_stmt(self):
        first_block = self._get_block(self._func.addr)

        for idx, stmt in enumerate(first_block.statements):
            if isinstance(stmt, ailment.Stmt.Store) \
                    and isinstance(stmt.addr, ailment.Expr.StackBaseOffset) \
                    and isinstance(stmt.data, ailment.Expr.Register) \
                    and stmt.data.reg_offset == self.project.arch.bp_offset \
                    and stmt.addr.offset < 0:
                return first_block, idx
            if isinstance(stmt, ailment.Stmt.Store) \
                    and isinstance(stmt.addr, ailment.Expr.StackBaseOffset) \
                    and isinstance(stmt.data, ailment.Expr.StackBaseOffset) \
                    and stmt.data.offset == 0 \
                    and stmt.addr.offset < 0:
                return first_block, idx


AnalysesHub.register_default('BasePointerSaveSimplifier',
                             BasePointerSaveSimplifier)
