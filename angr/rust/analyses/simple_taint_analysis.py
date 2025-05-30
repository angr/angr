from collections import defaultdict
from typing import List, Any


from angr.ailment import Expression, AILBlockWalkerBase, Block, Const, AILBlockWalker
from angr.ailment.statement import Call, Statement
from angr.analyses import Analysis, AnalysesHub
from angr.rust.mixins import CFAMixin


class SimpleTaintAnalysis(Analysis, CFAMixin):

    def __init__(
        self, graph, taint_set: List[Expression], sink_set: List[str], replacements=None, depth=0, max_depth=5
    ):
        CFAMixin.__init__(self, graph, self.project)
        self.graph = graph
        self.taint_set = taint_set
        self.sink_set = sink_set
        self.replacements = replacements or {}
        self.depth = depth
        self.max_depth = max_depth
        self.result = defaultdict(list)

        self._cfg = self.kb.cfgs.get_most_accurate()

        if depth <= max_depth:
            self._analyze()

    @staticmethod
    def get_clinic_arg_vvars(clinic):
        vvars = []
        for i in range(len(clinic.arg_vvars)):
            vvars.append(clinic.arg_vvars[i][0])
        return vvars

    @staticmethod
    def _contains_expr(parent_expr, sub_expr):
        class ExprFinder(AILBlockWalkerBase):
            def __init__(self):
                super().__init__()
                self.found = False

            def _handle_expr(
                self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
            ) -> Any:
                if expr.likes(sub_expr):
                    self.found = True
                else:
                    super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

        finder = ExprFinder()
        finder.walk_expression(parent_expr)
        return finder.found

    @staticmethod
    def _replace_expr(parent_expr, old_expr, new_expr):
        class ExprReplacer(AILBlockWalker):
            def __init__(self):
                super().__init__()

            def _handle_expr(
                self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
            ) -> Any:
                if expr.likes(old_expr):
                    return new_expr
                return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

        finder = ExprReplacer()
        new_expr = finder.walk_expression(parent_expr)
        return new_expr

    def _analyze(self):
        def callback(call: Call):
            if call.args:
                sink = self.match_call(call, self.sink_set)
                if sink:
                    for taint in self.taint_set:
                        for idx, arg in enumerate(call.args):
                            if self._contains_expr(arg, taint):
                                if taint in self.replacements:
                                    arg = self._replace_expr(arg, taint, self.replacements[taint])
                                self.result[(sink, idx)].append(arg)
                elif isinstance(call.target, Const) and call.target.value in self.kb.functions:
                    new_replacements = {}
                    for taint in self.taint_set:
                        for idx, arg in enumerate(call.args):
                            if self._contains_expr(arg, taint):
                                if taint in self.replacements:
                                    arg = self._replace_expr(arg, taint, self.replacements[taint])
                                new_replacements[idx] = arg
                    if new_replacements:
                        func = self.kb.functions[call.target.value]
                        cfg = self.kb.cfgs.get_most_accurate()
                        clinic = self.project.analyses.Clinic(func, cfg=cfg, optimization_passes=[])
                        arg_vvars = self.get_clinic_arg_vvars(clinic)
                        new_replacements = {
                            arg_vvars[idx]: replacement for idx, replacement in new_replacements.items()
                        }
                        sta = self.project.analyses.SimpleTaintAnalysis(
                            graph=clinic.graph,
                            taint_set=arg_vvars,
                            sink_set=self.sink_set,
                            replacements=new_replacements,
                            depth=self.depth + 1,
                            max_depth=self.max_depth,
                        )
                        for sink in sta.result:
                            self.result[sink] += sta.result[sink]

        class CallWalker(AILBlockWalkerBase):
            def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
                callback(stmt)
                super()._handle_Call(stmt_idx, stmt, block)

            def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
                callback(expr)
                super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)

        for block in self.graph.nodes:
            CallWalker().walk(block)


AnalysesHub.register_default("SimpleTaintAnalysis", SimpleTaintAnalysis)
