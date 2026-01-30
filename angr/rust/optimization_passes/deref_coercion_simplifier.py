import logging

from angr.ailment.block_walker import AILBlockRewriter
from angr.ailment import Block, BinaryOp, Const
from angr.ailment.expression import VirtualVariable, StringLiteral
from angr.ailment.statement import Call, Statement, FunctionLikeMacro

from angr.rust.sim_type import RustSimStruct
from angr.rust.optimization_passes.utils import CallRewriter
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.rust.mixins import CFAMixin, SRDAMixin

l = logging.getLogger(__file__)

STR_CMP_NE_FUNCTION = "<alloc::string::String as core::cmp::PartialEq<&str>>::ne"
STR_CMP_EQ_FUNCTION = "<alloc::string::String as core::cmp::PartialEq<&str>>::eq"


class StrCmpSimplifierWalker(AILBlockRewriter):
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
        return expr


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

    def _simplify_str_arguments(self, call: Call, block, stmt, is_expr):
        string_ty = self.project.kb.known_structs["alloc::string::String"]
        ptr_offset = (
                string_ty.get_field_offset("vec.buf.ptr.pointer")
                or string_ty.get_field_offset("vec.buf.inner.ptr.pointer")
                or 0
        )
        len_offset = string_ty.get_field_offset("vec.len") or self.project.arch.bytes
        if call.args:
            changed = False
            args = list(call.args)
            new_args = []
            while len(args) >= 2:
                arg0 = args.pop(0)
                vvar = arg0
                if isinstance(arg0, VirtualVariable) and vvar.was_stack:
                    vvar = self.get_stack_vvar_by_insn(vvar.stack_offset - ptr_offset, stmt.tags["ins_addr"],
                                                               block.idx)
                    if isinstance(vvar, VirtualVariable) and vvar.was_stack:
                        returnty = None
                        value = self.get_terminal_vvar_value(vvar)
                        if isinstance(value, FunctionLikeMacro):
                            returnty = value.returnty
                        elif isinstance(value, Call):
                            returnty = value.prototype.returnty
                        if isinstance(returnty, RustSimStruct) and returnty.name == string_ty.name:
                            arg1 = args.pop(0)
                            if (
                                    isinstance(arg1, VirtualVariable)
                                    and arg1.was_stack
                                    and arg1.stack_offset - arg0.stack_offset == len_offset - ptr_offset
                            ):
                                new_args.append(vvar)
                                changed = True
                                continue
                new_args.append(arg0)

            new_args.extend(args)
            if changed:
                new_stmt = call.copy()
                new_stmt.args = new_args
                return new_stmt
        return call

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        rewriter = CallRewriter(self._simplify_str_arguments)
        for block in self._graph.nodes():
            rewriter.walk(block)
        walker = StrCmpSimplifierWalker(self)
        for block in self._graph.nodes():
            walker.walk(block)
