from ailment.expression import BasePointerOffset, Load, VirtualVariable, VirtualVariableCategory
from ailment.statement import Assignment, Call

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.s_reaching_definitions import SRDAView
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE
from angr.rust.ailment.expression import Struct
from angr.rust.sim_type import RustSimStruct


class OwnershipSimplifier(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify ownership transfer operations"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.srda = self.project.analyses.SReachingDefinitions(subject=self._func, func_graph=self._graph)
        self.srda_view = SRDAView(self.srda.model)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _get_stack_vvar_by_insn(
        self, stack_offset: int, addr: int, block_idx: int | None = None
    ) -> VirtualVariable | None:
        vvars = set()

        def _predicate(stmt) -> bool:
            if (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and stmt.dst.stack_offset == stack_offset
            ):
                vvars.add(stmt.dst)
                return True
            return False

        self.srda_view._get_vvar_by_insn(addr, OP_BEFORE, _predicate, block_idx=block_idx)

        assert len(vvars) <= 1
        return next(iter(vvars), None)

    def _is_consecutive_copy(self, stmts):
        if len(stmts) == 1:
            return stmts[0].src.addr.offset
        stmts = sorted(stmts, key=lambda ele: ele.dst.stack_offset)
        stmt_ahead = stmts[0]
        for stmt in stmts[1:]:
            ahead_dst_offset, ahead_src_offset, ahead_size = self._get_stack_memcpy(stmt_ahead)
            dst_offset, src_offset, size = self._get_stack_memcpy(stmt)
            if not ahead_dst_offset + ahead_size == dst_offset or not ahead_src_offset + ahead_size == src_offset:
                return None
        return stmts[0].src.addr.offset

    def _get_stack_memcpy(self, stmt):
        if (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_stack
            and isinstance(stmt.src, Load)
            and isinstance(stmt.src.addr, BasePointerOffset)
        ):
            # return dst_offset, src_offset, size
            return stmt.dst.stack_offset, stmt.src.addr.offset, stmt.src.size
        return None, None, None

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            new_stmts = []
            stmts = list(block.statements)
            while len(stmts):
                stmt = stmts.pop(0)
                new_stmts.append(stmt)
                dst_offset, src_offset, size = self._get_stack_memcpy(stmt)
                if size:
                    # Is it copying from a struct object?
                    vvar = self._get_stack_vvar_by_insn(src_offset, stmt.ins_addr, block.idx)
                    value = self.srda_view.get_vvar_value(vvar) if vvar else None
                    struct_ty = None
                    if (
                        isinstance(value, Call)
                        and value.prototype
                        and isinstance(value.prototype.returnty, RustSimStruct)
                    ):
                        struct_ty = value.prototype.returnty
                    elif isinstance(value, Assignment) and isinstance(value.src, Struct):
                        struct_ty = value.src.type
                    if struct_ty:
                        is_ownership_transfer = False
                        cur_stmt = new_stmts.pop()
                        # Look ahead
                        sum_size = size
                        pending_stmts = [cur_stmt]
                        while len(new_stmts) and sum_size < struct_ty.size // 8:
                            stmt_ahead = new_stmts.pop()
                            ahead_dst_offset, ahead_src_offset, ahead_size = self._get_stack_memcpy(stmt_ahead)
                            if ahead_size:
                                sum_size += ahead_size
                                pending_stmts.insert(0, stmt_ahead)
                            else:
                                break
                        if sum_size == struct_ty.size // 8 and self._is_consecutive_copy(pending_stmts) == src_offset:
                            is_ownership_transfer = True
                        # Look back
                        if not is_ownership_transfer:
                            sum_size = size
                            pending_stmts = [cur_stmt]
                            while len(stmts) and sum_size < struct_ty.size // 8:
                                stmt_back = stmts.pop(0)
                                back_dst_offset, back_src_offset, back_size = self._get_stack_memcpy(stmt_back)
                                if back_size:
                                    sum_size += back_size
                                    pending_stmts.insert(0, stmt_back)
                                else:
                                    break
                            if (
                                sum_size == struct_ty.size // 8
                                and self._is_consecutive_copy(pending_stmts) == src_offset
                            ):
                                is_ownership_transfer = True
                        if is_ownership_transfer:
                            vvar_id = self.vvar_id_start
                            self.vvar_id_start += 1
                            vvar_bits = struct_ty.size
                            dst_vvar = VirtualVariable(
                                None,
                                vvar_id,
                                vvar_bits,
                                VirtualVariableCategory.STACK,
                                oident=dst_offset,
                                **pending_stmts[0].tags,
                            )
                            assignment = Assignment(idx=None, dst=dst_vvar, src=vvar, **dst_vvar.tags)
                            new_stmts.append(assignment)
                        else:
                            new_stmts.extend(pending_stmts)
            block.statements = new_stmts
