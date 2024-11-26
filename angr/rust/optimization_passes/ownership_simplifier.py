from collections import defaultdict

from ailment.expression import BasePointerOffset, Load, StackBaseOffset
from ailment.statement import Call, Store

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from angr.rust.sim_type import RustSimTypeFunction, RustSimTypeReference, is_composite_type
from ..mixins.srda_mixin import SRDAMixin
from ..mixins.dfa_mixin import DFAMixin
from ..mixins.cfa_mixin import CFAMixin


class OwnershipSimplifier(OptimizationPass, CFAMixin, DFAMixin, SRDAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify ownership transfer operations"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)
        DFAMixin.__init__(self)
        SRDAMixin.__init__(self, func, self._graph, self.project)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _is_consecutive_defs(self, defs):
        if len({(vvar_def.codeloc.block_addr, vvar_def.codeloc.block_idx) for vvar_def in defs}) != 1:
            return False
        idx_list = list(sorted(vvar_def.codeloc.stmt_idx for vvar_def in defs))
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

                    if struct_ty:
                        cur_offset = dst_offset
                        ins_addr = block.statements[-1].ins_addr
                        defs = []
                        while cur_offset - dst_offset < struct_ty.size // 8:
                            vvar = self.get_stack_vvar_by_insn(cur_offset, ins_addr, block.idx, OP_AFTER)
                            vvar_def = self.get_def_by_vvar(vvar) if vvar else None
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
                            addr = StackBaseOffset(None, self.project.arch.bits, dst_offset)
                            data = Load(
                                None,
                                StackBaseOffset(None, self.project.arch.bits, src_offset),
                                struct_ty.size // 8,
                                endness=self.project.arch.memory_endness,
                            )
                            # assignment = Assignment(idx=None, dst=dst_vvar, src=src, **stmt.tags)
                            replacement = Store(
                                idx=None,
                                addr=addr,
                                data=data,
                                size=data.size,
                                endness=self.project.arch.memory_endness,
                                **stmt.tags,
                            )
                            stmts_to_replace.append((block, defs[0].codeloc.stmt_idx, replacement))
                            for vvar_def in defs[1:]:
                                stmts_to_remove[block].add(block.statements[vvar_def.codeloc.stmt_idx])

        for block, stmt_idx, replacement in stmts_to_replace:
            block.statements[stmt_idx] = replacement

        for block in stmts_to_remove:
            stmts = stmts_to_remove[block]
            for stmt in stmts:
                block.statements.remove(stmt)
