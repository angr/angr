from ailment.expression import BasePointerOffset, Load
from ailment.statement import Store

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage


class OwnershipSimplifier(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify ownership transfer operations"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _is_potential_ownership_transfer(self, stmts):
        if len(stmts) < 2:
            return False
        sorted_seq = sorted(stmts, key=lambda ele: ele.addr.offset)
        last_addr_offset = sorted_seq[0].addr.offset
        last_data_offset = sorted_seq[0].data.addr.offset
        last_size = sorted_seq[0].data.size
        for stmt in sorted_seq[1:]:
            if (
                last_addr_offset + last_size != stmt.addr.offset
                or last_data_offset + last_size != stmt.data.addr.offset
            ):
                return False
        return True

    def _simplify_ownership_transfer_(self, stmts):
        new_stmts = []
        pending_stmts = []

        for stmt in stmts:
            if (
                len(pending_stmts) >= 2
                and self._is_potential_ownership_transfer(pending_stmts)
                and not self._is_potential_ownership_transfer(pending_stmts + [stmt])
            ):
                # Do the simplification
                pass
            pending_stmts.append(stmt)

        return new_stmts

    def _is_ownership_transfer(self, stmts):
        if len(stmts) < 2:
            return False
        addr_offset = stmts[0].addr.offset
        for stmt in stmts[1:]:
            if stmt.addr.offset + stmt.data.size == addr_offset:
                addr_offset = stmts[0].addr.offset
            else:
                return False
        return True

    def _merge_stores(self, stmts):
        first_stmt = stmts[0]
        last_stmt = stmts[-1].copy()
        last_stmt.addr = first_stmt.addr
        last_stmt.size = sum(stmt.size for stmt in stmts)
        last_stmt.data.size = last_stmt.size
        return last_stmt

    def _simplify_ownership_transfer(self, stmts):
        new_stmts = []
        pending_stmts = []

        for stmt in stmts:
            if len(pending_stmts) == 2 and not self._is_ownership_transfer(pending_stmts):
                new_stmts.append(pending_stmts[0])
                pending_stmts = pending_stmts[1:]
            elif (
                len(pending_stmts) >= 2
                and self._is_potential_ownership_transfer(pending_stmts)
                and not self._is_potential_ownership_transfer(pending_stmts + [stmt])
            ):
                new_stmts.append(self._merge_stores(pending_stmts))
                pending_stmts.clear()
            pending_stmts.append(stmt)
        if self._is_ownership_transfer(pending_stmts):
            new_stmts.append(self._merge_stores(pending_stmts))
            pending_stmts.clear()
        else:
            new_stmts += pending_stmts
        return new_stmts

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            new_stmts = []
            pending_stmts = []
            for stmt in block.statements:
                if (
                    isinstance(stmt, Store)
                    and isinstance(stmt.addr, BasePointerOffset)
                    and isinstance(stmt.data, Load)
                    and isinstance(stmt.data.addr, BasePointerOffset)
                ):
                    pending_stmts.append(stmt)
                else:
                    new_stmts += self._simplify_ownership_transfer(pending_stmts)
                    new_stmts.append(stmt)
                    pending_stmts.clear()
            # All pending statements should be handled now
            if len(pending_stmts) > 0:
                new_stmts += self._simplify_ownership_transfer(pending_stmts)
            block.statements = new_stmts
