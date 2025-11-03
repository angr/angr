import logging

from angr.ailment.expression import VirtualVariable
from angr.ailment.statement import Return, Label, Call
from angr.rust.mixins import CFAMixin, CFGTransformationMixin, SRDAMixin
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.utils.ail import find_call, get_terminal_call

CLEANUP_FUNCTIONS = ("free", "__rust_dealloc", "close", "core::ptr::drop_in_place", "core::ops::drop::Drop::drop")


l = logging.getLogger(__name__)


class CleanupCodeRemover(OptimizationPass, CFGTransformationMixin, CFAMixin, SRDAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Remove cleanup code"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        CFGTransformationMixin.__init__(self, self._graph)
        CFAMixin.__init__(self, self._graph, self.project)
        SRDAMixin.__init__(self, self._func, self._graph, self.project)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    @staticmethod
    def _is_simple_block(block):
        stmts = block.statements[:-1] if len(block.statements) > 0 else []
        return all(isinstance(stmt, Label) for stmt in stmts)

    def _should_remove(self, call):
        return self.match_call(call, CLEANUP_FUNCTIONS)

    def _remove_cleanup_calls(self):
        blocks_to_remove = set()
        for block in self._graph.nodes:
            if self._should_remove(get_terminal_call(block)):
                if isinstance(block.statements[-1], Return):
                    block.statements[-1].ret_exprs = []
                elif not self._is_simple_block(block):
                    l.debug(f"Removed the last statement of\n{block}")
                    block.statements = block.statements[:-1]
                else:
                    blocks_to_remove.add(block)
        for block in blocks_to_remove:
            self.remove_block(block)

    def _clean_return_exprs(self):
        for block in self._graph.nodes:
            if block.statements and isinstance(last_stmt := block.statements[-1], Return):
                call = find_call(last_stmt)
                last_stmt.ret_exprs = []
                if call and not self._should_remove(call):
                    call.bits = None
                    new_stmts = block.statements.copy()
                    new_stmts[-1] = call
                    new_stmts.append(last_stmt)
                    block.statements = new_stmts
        prototype = self._func.prototype
        if prototype:
            prototype = prototype.copy()
            prototype.returnty = None
            self._func.prototype = prototype

    def _adjust_returns_and_prototype(self):
        for block in self._graph.nodes:
            if block.statements and isinstance(last_stmt := block.statements[-1], Return):
                ret_expr = last_stmt.ret_exprs[0] if last_stmt.ret_exprs else None
                if isinstance(ret_expr, Call):
                    if self._should_remove(ret_expr):
                        self._clean_return_exprs()
                        break
                elif isinstance(ret_expr, VirtualVariable):
                    possible_values = self.get_terminal_vvar_values(ret_expr)
                    if any(isinstance(value, Call) and self._should_remove(value) for value in possible_values):
                        self._clean_return_exprs()
                        break

    def _analyze(self, cache=None):
        self._adjust_returns_and_prototype()
        self._remove_cleanup_calls()

        self.out_graph = self._simplify_graph(self._graph)
