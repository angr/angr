import logging

import ailment

from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class BasePointerSaveSimplifier(OptimizationPass):
    """
    Removes the effects of base pointer stack storage at function invocation and restoring at function return.
    """

    ARCHES = ['X86', 'AMD64', 'ARMEL', 'ARMHF', "ARMCortexM", "MIPS32", "MIPS64"]
    PLATFORMS = ["cgc", 'linux']
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify base pointer saving"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        save_stmt = self._find_baseptr_save_stmt()

        # Note that restoring statements may not exist since they can be effectively removed by other optimization
        restore_stmts = self._find_baseptr_restore_stmt()

        if save_stmt is None:
            return False, { }

        save_dst = save_stmt[2]
        if restore_stmts is not None:
            restore_srcs = [ tpl[2] for tpl in restore_stmts ]

            if all(src == save_dst for src in restore_srcs):
                return True, \
                       {
                           'save_stmt': save_stmt,
                           'restore_stmts': restore_stmts,
                       }

        return True, {
            'save_stmt': save_stmt,
            'restore_stmts': [ ]
        }

    def _analyze(self, cache=None):
        save_stmt = None
        restore_stmts = None

        if cache is not None:
            save_stmt = cache.get('save_stmt', None)
            restore_stmts = cache.get('restore_stmts', None)

        if save_stmt is None:
            save_stmt = self._find_baseptr_save_stmt()
        if restore_stmts is None:
            restore_stmts = self._find_baseptr_restore_stmt()

        if save_stmt is None:
            return

        # update the first block
        block, stmt_idx, _ = save_stmt
        block_copy = block.copy()
        block_copy.statements.pop(stmt_idx)
        self._update_block(block, block_copy)

        # update all endpoint blocks
        if restore_stmts:
            for block, stmt_idx, _ in restore_stmts:
                block_copy = block.copy()
                block_copy.statements.pop(stmt_idx)
                self._update_block(block, block_copy)

    def _find_baseptr_save_stmt(self):
        """
        Find the AIL statement that saves the base pointer to a stack slot.

        :return:    A tuple of (block_addr, statement_idx, save_dst) or None if not found.
        :rtype:     tuple|None
        """

        first_block = self._get_block(self._func.addr)
        if first_block is None:
            return None

        for idx, stmt in enumerate(first_block.statements):
            if isinstance(stmt, ailment.Stmt.Store) \
                    and isinstance(stmt.addr, ailment.Expr.StackBaseOffset) \
                    and isinstance(stmt.data, ailment.Expr.Register) \
                    and stmt.data.reg_offset == self.project.arch.bp_offset \
                    and stmt.addr.offset < 0:
                return first_block, idx, stmt.addr
            if isinstance(stmt, ailment.Stmt.Store) \
                    and isinstance(stmt.addr, ailment.Expr.StackBaseOffset) \
                    and isinstance(stmt.data, ailment.Expr.StackBaseOffset) \
                    and stmt.data.offset == 0 \
                    and stmt.addr.offset < 0:
                return first_block, idx, stmt.addr

        # Not found
        return None

    def _find_baseptr_restore_stmt(self):
        """
        Find the AIL statement that restores the base pointer from a stack slot.

        :return:    A list of tuples, where each tuple is like (block_addr, statement_idx, load_src), or None if not
                    found.
        :rtype:     list|None
        """

        endpoints = self._func.endpoints
        callouts_and_jumpouts = { n.addr for n in self._func.callout_sites + self._func.jumpout_sites }

        baseptr_restore_stmts = [ ]

        for endpoint in endpoints:
            for endpoint_block in self._get_blocks(endpoint.addr):
                for idx, stmt in enumerate(endpoint_block.statements):
                    if isinstance(stmt, ailment.Stmt.Assignment) \
                            and isinstance(stmt.dst, ailment.Expr.Register) \
                            and stmt.dst.reg_offset == self.project.arch.bp_offset \
                            and isinstance(stmt.src, ailment.Expr.Load) \
                            and isinstance(stmt.src.addr, ailment.Expr.StackBaseOffset):
                        baseptr_restore_stmts.append((endpoint_block, idx, stmt.src.addr))
                        break
                else:
                    if endpoint.addr not in callouts_and_jumpouts:
                        _l.debug("Could not find baseptr restoring statement in function %#x.", endpoint.addr)
                        return None
                    else:
                        _l.debug("No baseptr restoring statement is found at callout/jumpout site %#x. Might be expected.",
                                 endpoint.addr
                                 )

        return baseptr_restore_stmts
