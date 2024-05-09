from ...analyses.decompiler.ailgraph_walker import RemoveNodeNotice, AILGraphWalker
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from .utils import *
from ...utils.library import get_rust_function_name


class JunkRemover(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Remove redundant statements"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _handle_handle_alloc_error(self, block):
        pass

    def _handle_dealloc(self, block):
        pass

    def _handle_unwrap_failed(self, block):
        pass

    def _analyze(self, cache=None):
        def handle_node(node: ailment.Block):
            removed = False
            if node.statements:
                func = extract_callee(node.statements[-1], self.kb)
                if func:
                    demangled_name = get_rust_function_name(func.demangled_name)
                    if demangled_name in JunkHandlers:
                        removed = True
                        handler = JunkHandlers[demangled_name]
                        handler(self, node)
            if removed:
                preds = list(pred for pred in self._graph.predecessors(node) if pred is not node)
                succs = list(succ for succ in self._graph.successors(node) if succ is not node)
                if len(preds) == 1 and len(succs) == 0:
                    pred = preds[0]
                    value_updated = False
                    if pred.statements and isinstance(pred.statements[-1], ailment.Stmt.ConditionalJump):
                        last_stmt = pred.statements[-1]
                        if (
                            isinstance(last_stmt.true_target, ailment.Expr.Const)
                            and last_stmt.true_target.value == node.addr
                        ):
                            value_updated = True
                            last_stmt = ailment.Stmt.Jump(
                                last_stmt.idx,
                                last_stmt.true_target,
                                last_stmt.true_target_idx,
                                ins_addr=last_stmt.ins_addr,
                            )
                        elif (
                            isinstance(last_stmt.true_target, ailment.Expr.Const)
                            and last_stmt.false_target.value == node.addr
                        ):
                            value_updated = True
                            last_stmt = ailment.Stmt.Jump(
                                last_stmt.idx,
                                last_stmt.false_target,
                                last_stmt.false_target_idx,
                                ins_addr=last_stmt.ins_addr,
                            )
                        pred.statements[-1] = last_stmt
                        if value_updated:
                            raise RemoveNodeNotice()
                elif len(preds) == 1 and len(succs) == 1:
                    pred = preds[0]
                    succ = succs[0]
                    value_updated = False
                    # update the last statement of pred
                    if pred.statements and isinstance(pred.statements[-1], ailment.Stmt.ConditionalJump):
                        last_stmt = pred.statements[-1]
                        if (
                            isinstance(last_stmt.true_target, ailment.Expr.Const)
                            and last_stmt.true_target.value == node.addr
                        ):
                            last_stmt.true_target.value = succ.addr
                            value_updated = True
                        if (
                            isinstance(last_stmt.false_target, ailment.Expr.Const)
                            and last_stmt.false_target.value == node.addr
                        ):
                            last_stmt.false_target.value = succ.addr
                            value_updated = True
                        if (
                            isinstance(last_stmt.true_target, ailment.Expr.Const)
                            and isinstance(last_stmt.false_target, ailment.Expr.Const)
                            and last_stmt.true_target.value == last_stmt.false_target.value
                        ):
                            last_stmt = ailment.Stmt.Jump(
                                last_stmt.idx,
                                last_stmt.true_target,
                                last_stmt.true_target_idx,
                                ins_addr=last_stmt.ins_addr,
                            )
                        pred.statements[-1] = last_stmt

                    if value_updated:
                        self._graph.add_edge(pred, succ)
                        raise RemoveNodeNotice()
                elif len(preds) >= 1 and len(succs) == 1:
                    succ = succs[0]
                    branch_updates = 0
                    for pred in preds:
                        # test how many last statements of pred can potentially be updated
                        if pred.statements and isinstance(pred.statements[-1], ailment.Stmt.ConditionalJump):
                            last_stmt = pred.statements[-1]
                            if (
                                isinstance(last_stmt.true_target, ailment.Expr.Const)
                                and last_stmt.true_target.value == node.addr
                            ):
                                branch_updates += 1
                            if (
                                isinstance(last_stmt.false_target, ailment.Expr.Const)
                                and last_stmt.false_target.value == node.addr
                            ):
                                branch_updates += 1

                    if branch_updates == len(preds):
                        # actually do the update
                        for pred in preds:
                            self._graph.add_edge(pred, succ)
                            if pred.statements and isinstance(pred.statements[-1], ailment.Stmt.ConditionalJump):
                                last_stmt = pred.statements[-1]
                                if (
                                    isinstance(last_stmt.true_target, ailment.Expr.Const)
                                    and last_stmt.true_target.value == node.addr
                                ):
                                    last_stmt.true_target.value = succ.addr
                                if (
                                    isinstance(last_stmt.false_target, ailment.Expr.Const)
                                    and last_stmt.false_target.value == node.addr
                                ):
                                    last_stmt.false_target.value = succ.addr
                        raise RemoveNodeNotice()
                elif not preds or not succs:
                    raise RemoveNodeNotice()

        AILGraphWalker(self._graph, handle_node, replace_nodes=True).walk()


JunkHandlers = {
    "alloc::alloc::handle_alloc_error": JunkRemover._handle_handle_alloc_error,
    "__rust_dealloc": JunkRemover._handle_dealloc,
    "core::result::unwrap_failed": JunkRemover._handle_unwrap_failed,
}
