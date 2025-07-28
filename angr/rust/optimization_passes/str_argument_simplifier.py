from angr.ailment import AILBlockWalker, Block, Const
from angr.ailment.statement import Call, Statement
from angr.ailment.expression import StringLiteral

from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage


class StrArgumentSimplifierWalker(AILBlockWalker):
    def __init__(self, context: "StrArgumentSimplifier"):
        super().__init__()
        self.context = context
        self.project = context.project

    def _extract_str(self, ptr_expr: Const, len_expr: Const):
        decoded_str = None
        memory = self.project.loader.memory
        str_addr = ptr_expr.value
        str_len = len_expr.value
        if str_len >= 0 and (
            (section := self.project.loader.find_section_containing(ptr_expr.value))
            and section.is_readable
            and not section.is_writable
        ):
            try:
                decoded_str = memory.load(str_addr, str_len).decode("utf-8")
                decoded_str = (
                    decoded_str
                    if decoded_str.replace("\n", "").replace("\t", "").replace("\r", "").isprintable()
                    else None
                )
            except UnicodeDecodeError:
                pass
        return decoded_str

    def _simplify_call(self, call: Call):
        args = call.args
        new_args = []
        changed = False
        if args:
            args = list(args)
            while args:
                arg0 = args.pop(0)
                arg1 = args.pop(0) if args else None
                if (
                    isinstance(arg0, Const)
                    and isinstance(arg1, Const)
                    and (decoded_str := self._extract_str(arg0, arg1))
                ):
                    new_arg = StringLiteral(None, decoded_str, self.project.arch.bits)
                    new_args.append(new_arg)
                    changed = True
                else:
                    new_args.append(arg0)
                    if arg1:
                        args.insert(0, arg1)
        if changed:
            new_call = call.copy()
            new_call.args = new_args
            return new_call
        return None

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        new_expr = super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)
        if new_expr is None:
            return self._simplify_call(expr)
        return self._simplify_call(new_expr) or new_expr

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        new_stmt = super()._handle_Call(stmt_idx, stmt, block)
        if block:
            new_stmt = self._simplify_call(new_stmt if new_stmt else stmt)
            if new_stmt:
                block.statements[stmt_idx] = new_stmt
        return new_stmt


class StrArgumentSimplifier(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Simplify string literals used as function call arguments"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        walker = StrArgumentSimplifierWalker(self)
        for block in self._graph.nodes:
            walker.walk(block)
