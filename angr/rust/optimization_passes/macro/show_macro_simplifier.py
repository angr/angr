from ailment.expression import StackBaseOffset, VirtualVariable, StringLiteral
from ailment.statement import Call, Assignment, FunctionLikeMacro

from angr.utils.graph import GraphUtils
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.mixins.cfa_mixin import CFAMixin

UIOERROR_NEW_FUNCTION = ("uucore::mods::error::UIoError::new",)
SET_EXIT_CODE_FUNCTION = ("uucore::mods::error::set_exit_code",)
UTIL_NAME_FUNCTION = ("uucore::util_name",)
SHOW_ERROR_OR_WARNING_MACROS = {
    "{}: ": "show_error",
    "{}: warning: ": "show_warning",
    "{}: WARNING: ": "show_warning_caps",
}


class ShowMacroSimplifier(OptimizationPass, CFAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Recover show-family macros in coreutils"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)

        self._stmts_to_remove = {}
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _find_util_name_call(self, block, expr):
        if isinstance(expr, StackBaseOffset):
            for stmt_idx, stmt in enumerate(block.statements):
                if (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and stmt.dst.was_stack
                    and stmt.dst.stack_offset == expr.offset
                    and isinstance(stmt.src, Call)
                    and self.match_call(stmt.src, UTIL_NAME_FUNCTION)
                ):
                    return stmt_idx
        return None

    def _try_simplify_show(self, block):
        if self.num_successors(block) == 1:
            next_block = self.get_one_successor(block)
            if self.match_call(block, UIOERROR_NEW_FUNCTION) and self.match_call(next_block, SET_EXIT_CODE_FUNCTION):
                cur_block = next_block
                cnt = 5
                while self.num_successors(cur_block) == 1 and cnt > 0:
                    cnt -= 1
                    cur_block = self.get_one_successor(cur_block)
                    macro = self.last_stmt(cur_block)
                    if (
                        isinstance(macro, FunctionLikeMacro)
                        and macro.name == "eprintln"
                        and isinstance(macro.args[0], StringLiteral)
                        and macro.args[0].decoded_str == "{}: {}"
                        and len(macro.args) == 3
                    ):
                        stmt_idx = self._find_util_name_call(cur_block, macro.args[1])
                        if stmt_idx is not None:
                            cur_block.statements.pop(stmt_idx)
                            macro.name = "show"
                            macro.args = macro.args[2:]
                            block.statements.pop(-1)
                            next_block.statements.pop(-1)
                            break

    def _try_simplify_show_error_or_warning(self, block):
        if self.num_successors(block) == 1:
            next_block = self.get_one_successor(block)
            first_macro = self.last_stmt(block)
            second_macro = self.last_stmt(next_block)
            if isinstance(first_macro, Assignment):
                first_macro = first_macro.src
            if isinstance(second_macro, Assignment):
                second_macro = second_macro.src
            if (
                isinstance(first_macro, FunctionLikeMacro)
                and isinstance(second_macro, FunctionLikeMacro)
                and first_macro.name == "eprint"
                and second_macro.name == "eprintln"
                and isinstance(first_macro.args[0], StringLiteral)
            ):
                first_fmt_str = first_macro.args[0].decoded_str
                # second_fmt_str = second_macro.args[0].decoded_str
                if first_fmt_str in SHOW_ERROR_OR_WARNING_MACROS:
                    first_macro_arg = first_macro.args[1]
                    # second_macro_arg = second_macro.args[1]
                    stmt_idx = self._find_util_name_call(block, first_macro_arg)
                    if stmt_idx is not None:
                        block.statements.pop(stmt_idx)
                        block.statements.pop(-1)
                        macro_name = SHOW_ERROR_OR_WARNING_MACROS[first_fmt_str]
                        second_macro.name = macro_name

    def _analyze(self, cache=None):
        for block in list(GraphUtils.quasi_topological_sort_nodes(self._graph, list(self._graph.nodes))):
            self._try_simplify_show(block)
            self._try_simplify_show_error_or_warning(block)
