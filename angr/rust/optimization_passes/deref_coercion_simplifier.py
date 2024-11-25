from typing import Any

from ailment import AILBlockWalker, Block, Expression, BinaryOp
from ailment.expression import VirtualVariable
from ailment.statement import Call, Statement, Assignment

from ..sim_type import RustSimTypeVec
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ...rust.mixins.cfa_mixin import CFAMixin
from ...rust.mixins.srda_mixin import SRDAMixin

VEC_DEREF_FUNCTION = ["<alloc::vec::Vec<T,A> as core::ops::deref::Deref>::deref"]


class DerefCoercionSimplifierWalker(AILBlockWalker):
    def __init__(self, context: "DerefCoercionSimplifier"):
        super().__init__()
        self.context = context
        self.calls_to_remove = set()

    def handle_Call(self, stmt: Call) -> Call | None:
        if stmt.args:
            changed = False
            args = list(stmt.args)
            new_args = []
            while len(args) >= 2:
                arg0 = args.pop(0)
                arg1 = args.pop(0)
                if isinstance(arg0, VirtualVariable) and (
                    (value := self.context.get_terminal_vvar_value(arg0))
                    and isinstance(value, Call)
                    and value.args
                    and len(value.args) == 1
                    and self.context.match_call(value, VEC_DEREF_FUNCTION, monopolize=False, use_trait_name=False)
                ):
                    new_arg = value.args[0]
                    new_args.append(new_arg)
                    changed = True
                    self.calls_to_remove.add(value)
                elif (
                    isinstance(arg0, BinaryOp)
                    and arg0.op == "AccessField"
                    and isinstance(arg1, BinaryOp)
                    and arg1.op == "AccessField"
                    and isinstance(arg0.tags["struct_type"], RustSimTypeVec)
                    and isinstance(arg1.tags["struct_type"], RustSimTypeVec)
                    and arg0.tags["field_name"] == "ptr"
                    and arg1.tags["field_name"] == "len"
                ):
                    new_arg = arg0.operands[0]
                    new_args.append(new_arg)
                    changed = True
                else:
                    new_args.append(arg0)
                    args.append(arg1)
            new_args.extend(args)
            if changed:
                new_call = stmt.copy()
                new_call.args = new_args
                return new_call
        return None

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        final_stmt = self.handle_Call(stmt)
        if block and final_stmt:
            block.statements[stmt_idx] = final_stmt

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        return self.handle_Call(expr)


class DerefCoercionSimplifier(OptimizationPass, SRDAMixin, CFAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Correct variable types overridden by other Rust optimization passes"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        SRDAMixin.__init__(self, func, self._graph, self.project)
        CFAMixin.__init__(self, self._graph, self.project)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        walker = DerefCoercionSimplifierWalker(self)
        for block in self._graph.nodes():
            walker.walk(block)
        for block in self._graph.nodes:
            stmts_to_remove = set()
            for stmt in block.statements:
                if isinstance(stmt, Call) and any(call.likes(stmt) for call in walker.calls_to_remove):
                    stmts_to_remove.add(stmt)
                if (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.src, Call)
                    and any(call.likes(stmt.src) for call in walker.calls_to_remove)
                ):
                    stmts_to_remove.add(stmt)
            for stmt in stmts_to_remove:
                block.statements.remove(stmt)
