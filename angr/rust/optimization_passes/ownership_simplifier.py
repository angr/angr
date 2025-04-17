from collections import defaultdict

from ailment.expression import BasePointerOffset, Load, StackBaseOffset
from ailment.statement import Call, Store, Assignment, FunctionLikeMacro

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from angr.rust.sim_type import RustSimTypeFunction, RustSimTypeReference, is_composite_type
from .base import SSAVariableHelper
from ..mixins.srda_mixin import SRDAMixin
from ..mixins.dfa_mixin import DFAMixin
from ..mixins.cfa_mixin import CFAMixin
from ...code_location import CodeLocation


class OwnershipSimplifier(OptimizationPass, CFAMixin, DFAMixin, SRDAMixin, SSAVariableHelper):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.RUST_SPECIFIC_SIMPLIFICATION
    NAME = "Simplify ownership transfer operations"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)
        DFAMixin.__init__(self)
        SRDAMixin.__init__(self, func, self._graph, self.project)
        SSAVariableHelper.__init__(self, self)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _is_consecutive_defs(self, defs):
        if len({(vvar_def.block_addr, vvar_def.block_idx) for vvar_def in defs}) != 1:
            return False
        idx_list = list(sorted(vvar_def.stmt_idx for vvar_def in defs))
        return idx_list == list(range(idx_list[0], idx_list[0] + len(idx_list)))

    def _analyze(self, cache=None):
        stmts_to_replace = []
        stmts_to_remove = defaultdict(set)
        for block in self._graph.nodes:
            for stmt in block.statements:
                dst_offset, src_offset, size = self.extract_stack_data_flow(stmt)
                if size:
                    struct_ty = None
                    # Is it used as a struct argument?
                    call = self.terminal_call(block)
                    if call and isinstance(call.prototype, RustSimTypeFunction) and call.args:
                        for arg_ty, arg in zip(call.prototype.args, call.args):
                            if (
                                isinstance(arg, BasePointerOffset)
                                and isinstance(arg_ty, RustSimTypeReference)
                                and is_composite_type(arg_ty.pts_to)
                                and arg.offset == dst_offset
                            ):
                                struct_ty = arg_ty.pts_to
                                break
                    # Is it copying from a struct object?
                    if not struct_ty:
                        vvar = self.get_stack_vvar_by_insn(src_offset, stmt.ins_addr, block.idx)
                        value = self.get_terminal_vvar_value(vvar) if vvar else None
                        if isinstance(value, Call) and value.prototype and is_composite_type(value.prototype.returnty):
                            struct_ty = value.prototype.returnty
                        elif isinstance(value, FunctionLikeMacro):
                            struct_ty = value.returnty

                    if struct_ty:
                        cur_offset = dst_offset
                        ins_addr = block.statements[-1].ins_addr
                        defs = []
                        while cur_offset - dst_offset < struct_ty.size // 8:
                            # Workaround: In case the Store statement is not ssailified
                            value = None
                            for stmt_idx, stmt in enumerate(block.statements):
                                if (
                                    isinstance(stmt, Store)
                                    and isinstance(stmt.addr, StackBaseOffset)
                                    and stmt.addr.offset == cur_offset
                                ):
                                    value = stmt.data
                                    codeloc = CodeLocation(
                                        block.addr, stmt_idx, block_idx=block.idx, ins_addr=stmt.ins_addr
                                    )
                                    defs.append(codeloc)
                            if not value:
                                vvar = self.get_stack_vvar_by_insn(cur_offset, ins_addr, block.idx, op_type=OP_AFTER)
                                def_ = self.get_def_by_vvar(vvar) if vvar else None
                                if vvar and def_:
                                    value = self.get_vvar_value(vvar)
                                    codeloc = def_.codeloc
                                    defs.append(codeloc)

                            if not value:
                                break
                            cur_offset += value.size
                        # If it's ownership transfer
                        if (
                            cur_offset - dst_offset == struct_ty.size // 8
                            and (block.addr, block.idx) == (defs[0].block_addr, defs[0].block_idx)
                            and self._is_consecutive_defs(defs)
                        ):
                            dst_vvar = self.new_stack_vvar(dst_offset, struct_ty.size, {"ins_addr": block.addr})
                            # addr = StackBaseOffset(None, self.project.arch.bits, dst_offset)
                            src_vvar = self.get_stack_vvar_by_insn(
                                src_offset,
                                block.statements[-1].ins_addr,
                                block.idx,
                                size=struct_ty.size // 8,
                                op_type=OP_AFTER,
                            )
                            data = src_vvar or Load(
                                None,
                                StackBaseOffset(None, self.project.arch.bits, src_offset),
                                struct_ty.size // 8,
                                endness=self.project.arch.memory_endness,
                            )
                            replacement = Assignment(idx=None, dst=dst_vvar, src=data, ins_addr=block.addr)
                            # replacement = Store(
                            #     idx=None,
                            #     addr=addr,
                            #     data=data,
                            #     size=data.size,
                            #     endness=self.project.arch.memory_endness,
                            #     **stmt.tags,
                            # )
                            stmts_to_replace.append((block, defs[0].stmt_idx, replacement))
                            for vvar_def in defs[1:]:
                                stmts_to_remove[block].add(block.statements[vvar_def.stmt_idx])

        for block, stmt_idx, replacement in stmts_to_replace:
            block.statements[stmt_idx] = replacement

        for block in stmts_to_remove:
            stmts = stmts_to_remove[block]
            for stmt in stmts:
                block.statements.remove(stmt)
