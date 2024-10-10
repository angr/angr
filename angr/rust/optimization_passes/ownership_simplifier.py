from collections import defaultdict

from ailment.expression import BasePointerOffset, Load, VirtualVariable, VirtualVariableCategory, StackBaseOffset
from ailment.statement import Assignment, Call

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from angr.rust.ailment.expression import Struct
from angr.rust.sim_type import RustSimStruct, RustSimTypeFunction, RustSimTypeReference
from angr.rust.utils.ail_util import get_terminal_call
from angr.rust.utils.srda_util import SRDAUtil


class OwnershipSimplifier(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify ownership transfer operations"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.srda_util = SRDAUtil.from_function(self.project, func, self._graph)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

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

    def _is_consecutive_defs(self, defs):
        if len({(vvar_def.codeloc.block_addr, vvar_def.codeloc.block_idx) for vvar_def in defs}) != 1:
            return False
        idx_list = list(sorted(vvar_def.codeloc.stmt_idx for vvar_def in defs))
        return idx_list == list(range(idx_list[0], idx_list[0] + len(idx_list)))

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
        elif (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_stack
            and isinstance(stmt.src, VirtualVariable)
            and stmt.src.was_stack
        ):
            # return dst_offset, src_offset, size
            return stmt.dst.stack_offset, stmt.src.stack_offset, stmt.src.size
        return None, None, None

    def _analyze(self, cache=None):
        stmts_to_replace = []
        stmts_to_remove = defaultdict(set)
        for block in self._graph.nodes:
            for stmt in block.statements:
                dst_offset, src_offset, size = self._get_stack_memcpy(stmt)
                if size:
                    struct_ty = None
                    # Is it used as a struct argument?
                    call = get_terminal_call(block)
                    if call and isinstance(call.prototype, RustSimTypeFunction) and call.args:
                        for arg_ty, arg in zip(call.prototype.args, call.args):
                            if (
                                isinstance(arg, BasePointerOffset)
                                and isinstance(arg_ty, RustSimTypeReference)
                                and isinstance(arg_ty.pts_to, RustSimStruct)
                                and arg.offset == dst_offset
                            ):
                                struct_ty = arg_ty.pts_to
                                break
                    # Is it copying from a struct object?
                    if not struct_ty:
                        vvar = self.srda_util.get_stack_vvar_by_insn(src_offset, stmt.ins_addr, block.idx)
                        value = self.srda_util.srda_view.get_vvar_value(vvar) if vvar else None
                        if (
                            isinstance(value, Call)
                            and value.prototype
                            and isinstance(value.prototype.returnty, RustSimStruct)
                        ):
                            struct_ty = value.prototype.returnty
                        elif isinstance(value, Assignment) and isinstance(value.src, Struct):
                            struct_ty = value.src.type

                    if struct_ty:
                        cur_offset = dst_offset
                        ins_addr = block.statements[-1].ins_addr
                        defs = []
                        while cur_offset - dst_offset < struct_ty.size // 8:
                            vvar = self.srda_util.get_stack_vvar_by_insn(cur_offset, ins_addr, block.idx, OP_AFTER)
                            vvar_def = self.srda_util.get_def_by_vvar(vvar) if vvar else None
                            if not vvar_def:
                                break
                            defs.append(vvar_def)
                            cur_offset += vvar.size
                        # If it's ownership transfer
                        if (
                            cur_offset - dst_offset == struct_ty.size // 8
                            and (block.addr, block.idx) == (defs[0].codeloc.block_addr, defs[0].codeloc.block_idx)
                            and self._is_consecutive_defs(defs)
                        ):
                            vvar_id = self.vvar_id_start
                            self.vvar_id_start += 1
                            vvar_bits = struct_ty.size
                            dst_vvar = VirtualVariable(
                                None,
                                vvar_id,
                                vvar_bits,
                                VirtualVariableCategory.STACK,
                                oident=dst_offset,
                                **stmt.tags,
                            )
                            src = Load(
                                None,
                                StackBaseOffset(None, self.project.arch.bits, src_offset),
                                vvar_bits // 8,
                                endness=self.project.arch.memory_endness,
                            )
                            assignment = Assignment(idx=None, dst=dst_vvar, src=src, **stmt.tags)
                            stmts_to_replace.append((block, defs[0].codeloc.stmt_idx, assignment))
                            for vvar_def in defs[1:]:
                                stmts_to_remove[block].add(block.statements[vvar_def.codeloc.stmt_idx])

        for block, stmt_idx, replacement in stmts_to_replace:
            block.statements[stmt_idx] = replacement

        for block in stmts_to_remove:
            stmts = stmts_to_remove[block]
            for stmt in stmts:
                block.statements.remove(stmt)
