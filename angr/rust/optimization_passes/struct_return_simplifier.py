from collections import defaultdict
from typing import Tuple

from ailment import Block
from ailment.expression import VirtualVariable, BinaryOp, Const
from ailment.statement import Return, Store

from angr.analyses.decompiler.optimization_passes.optimization_pass import (
    OptimizationPassStage,
    SequenceOptimizationPass,
)
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structuring.structurer_nodes import SequenceNode
from angr.rust.ailment.expression import Struct
from angr.rust.sim_type import RustSimTypeInt, RustSimStruct


class StructReturnWalker(SequenceWalker):
    def __init__(self, context: "StructReturnSimplifier"):
        super().__init__()
        self.context = context

    def _get_vvar_and_offset(self, expr) -> Tuple[VirtualVariable | None, int | None]:
        if isinstance(expr, VirtualVariable):
            return expr, 0
        elif (
            isinstance(expr, BinaryOp)
            and expr.op == "Add"
            and isinstance(expr.operands[0], VirtualVariable)
            and isinstance(expr.operands[1], Const)
        ):
            return expr.operands[0], expr.operands[1].value
        return None, None

    def _build_struct_ty(self, fields):
        ty_fields = {}
        for offset in sorted(fields.keys()):
            expr = fields[offset]
            arg_ty = RustSimTypeInt(expr.bits, signed=False)
            ty_fields[f"field_{offset}"] = arg_ty
        struct_ty = RustSimStruct(
            ty_fields,
            name=f"struct{sum(field.size if field.size else 0 for field in ty_fields.values()) // 8}",
            pack=True,
        ).with_arch(self.context.project.arch)
        return struct_ty

    def collect_ret_expr(self, blocks):
        stmts_to_remove = defaultdict(list)
        fields = {}
        for block in blocks:
            for stmt in block.statements:
                if isinstance(stmt, Store):
                    vvar, offset = self._get_vvar_and_offset(stmt.addr)
                    if vvar and vvar.was_parameter and vvar.varid == 0:
                        stmts_to_remove[block].append(stmt)
                        fields[offset] = stmt.data
        if 0 in fields:
            struct_ty = self._build_struct_ty(fields)
            result = Struct(0, fields, struct_ty)
            return stmts_to_remove, result
        return None, None

    def _handle_Sequence(self, seq: SequenceNode, **kwargs):
        last_node = seq.nodes[-1]
        if isinstance(last_node, Block) and last_node.statements and isinstance(last_node.statements[-1], Return):
            blocks = []
            for node in reversed(seq.nodes):
                if not isinstance(node, Block):
                    break
                blocks.append(node)
            stmts_to_remove, struct_expr = self.collect_ret_expr(blocks)
            if struct_expr:
                last_node.statements[-1].ret_exprs = [struct_expr]
                for block in stmts_to_remove:
                    for stmt in stmts_to_remove[block]:
                        block.statements.remove(stmt)
        super()._handle_Sequence(seq, **kwargs)


class StructReturnSimplifier(SequenceOptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "Simplify function return sites"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self._graph = kwargs.get("graph")
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        StructReturnWalker(self).walk(self.seq)
        self.out_seq = self.seq
        # for block in self._graph.nodes:
        #     if block.statements and isinstance(block.statements[-1], Return):
        #         ret = block.statements[-1]
        #         if ret.ret_exprs and not isinstance(ret.ret_exprs[0], Struct):
        #             import ipdb
        #
        #             ipdb.set_trace()
