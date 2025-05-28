from ailment import AILBlockWalker, Block, BinaryOp, Const
from ailment.expression import VirtualVariable, Load, StringLiteral
from ailment.statement import Call, Statement, FunctionLikeMacro

from ..utils.ail import unwrap_stack_vvar_reference
from angr.rust.sim_type import RustSimStruct
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.rust.mixins import CFAMixin, SRDAMixin

STR_CMP_NE_FUNCTION = "<alloc::string::String as core::cmp::PartialEq<&str>>::ne"
STR_CMP_EQ_FUNCTION = "<alloc::string::String as core::cmp::PartialEq<&str>>::eq"


class DerefCoercionSimplifierWalker(AILBlockWalker):
    def __init__(self, context: "DerefCoercionSimplifier"):
        super().__init__()
        self.context = context

    def handle_Call(self, call: Call, stmt, block):
        String_ty = self.context.project.kb.known_structs["alloc::string::String"]
        if call.args:
            changed = False
            args = list(call.args)
            new_args = []
            while len(args) >= 2:
                arg0 = args.pop(0)
                vvar = arg0
                if isinstance(vvar, VirtualVariable) and vvar.was_stack:
                    vvar = self.context.get_stack_vvar_by_insn(
                        vvar.stack_offset - self.context.project.arch.bytes, stmt.ins_addr, block.idx
                    )
                if isinstance(vvar, Load) and (vvar := unwrap_stack_vvar_reference(vvar.addr)):
                    vvar = self.context.get_stack_vvar_by_insn(
                        vvar.stack_offset - self.context.project.arch.bytes, stmt.ins_addr, block.idx
                    )
                if isinstance(vvar, VirtualVariable) and vvar.was_stack:
                    returnty = None
                    if self.context.match_call(call, [STR_CMP_NE_FUNCTION], monopolize=False, use_trait_name=False):
                        returnty = String_ty.with_arch(self.context.project.arch)
                    elif self.context.match_call(call, [STR_CMP_EQ_FUNCTION], monopolize=False, use_trait_name=False):
                        returnty = String_ty.with_arch(self.context.project.arch)
                    else:
                        value = self.context.get_terminal_vvar_value(vvar)
                        if isinstance(value, FunctionLikeMacro):
                            returnty = value.returnty
                        elif isinstance(value, Call):
                            returnty = value.prototype.returnty
                    if isinstance(returnty, RustSimStruct) and returnty == String_ty.name:
                        args.pop(0)
                        new_args.append(vvar)
                        changed = True
                        continue
                new_args.append(arg0)

            new_args.extend(args)
            if changed:
                new_stmt = call.copy()
                new_stmt.args = new_args
                return new_stmt
        return None

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        final_stmt = self.handle_Call(stmt, stmt, block)
        if block and final_stmt:
            block.statements[stmt_idx] = final_stmt

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        return self.handle_Call(expr, stmt, block)


class StrCmpSimplifierWalker(AILBlockWalker):
    def __init__(self, context: "DerefCoercionSimplifier"):
        super().__init__()
        self.context = context

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
        if expr.op == "CmpEQ" and isinstance(expr.operands[1], Const) and expr.operands[1].value == 0:
            if (
                isinstance(expr.operands[0], Call)
                and expr.operands[0].args
                and self.context.match_call(
                    expr.operands[0], [STR_CMP_NE_FUNCTION, STR_CMP_EQ_FUNCTION], monopolize=False, use_trait_name=False
                )
            ):
                op = (
                    "CmpNE"
                    if self.context.match_call(
                        expr.operands[0], STR_CMP_NE_FUNCTION, monopolize=False, use_trait_name=False
                    )
                    else "CmpEQ"
                )
                operands = list(expr.operands[0].args)
                if len(operands) == 1:
                    operands.append(StringLiteral(None, "", operands[0].bits))
                if len(operands) == 2:
                    return BinaryOp(None, op, operands, **expr.tags)
        return None


class DerefCoercionSimplifier(OptimizationPass, SRDAMixin, CFAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Simplify explict deref coercion operations"

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
        walker = StrCmpSimplifierWalker(self)
        for block in self._graph.nodes():
            walker.walk(block)
