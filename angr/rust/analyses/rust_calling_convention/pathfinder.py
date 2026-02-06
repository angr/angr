from networkx.classes import DiGraph
from networkx.exception import NetworkXError

from angr.ailment import AILBlockRewriter
from angr.rust.mixins import SRDAMixin
from angr.rust.utils.ail import has_call, extract_vvar_and_offset
from angr.ailment.statement import Return, Jump, ConditionalJump, Label, Assignment, Statement, Store
from angr.ailment.expression import Phi, VirtualVariable
from angr.ailment import Block
from angr.utils.graph import GraphUtils


class Pathfinder:

    def __init__(self, graph, srda_mixin: SRDAMixin = None):
        self.graph = graph
        self._srda_mixin = srda_mixin

    @staticmethod
    def _is_safe_block(block):
        return all(
            isinstance(stmt, (Return, Jump, ConditionalJump, Label, Assignment)) for stmt in block.statements
        ) and not has_call(block)

    @staticmethod
    def _remove_phi(path):
        new_path = [block.copy() for block in path]

        class PhiRewriter(AILBlockRewriter):

            def __init__(self):
                super().__init__()
                self.pred_block = None

            def _handle_Phi(
                self, expr_id: int, expr: Phi, stmt_idx: int, stmt: Statement, block: Block | None
            ) -> Phi | None:
                if self.pred_block:
                    pred = (self.pred_block.addr, self.pred_block.idx)
                    for src, vvar in expr.src_and_vvars:
                        if src == pred:
                            return vvar
                return expr

        rewriter = PhiRewriter()
        for block in new_path:
            rewriter.walk(block)
            rewriter.pred_block = block
        return tuple(new_path)

    def _is_ret2arg0_block(self, block):
        for stmt in reversed(block.statements):
            if isinstance(stmt, Store):
                vvar, _ = extract_vvar_and_offset(stmt.addr)
                if isinstance(vvar, VirtualVariable) and self._srda_mixin:
                    vvar = self._srda_mixin.get_terminal_vvar(vvar)
                if isinstance(vvar, VirtualVariable) and vvar.was_parameter and vvar.varid == 0:
                    return True
        return False

    def _find_ret2arg0_path(self, head_block, visited):
        visited.add(head_block)
        paths = [[head_block]]
        changed = True
        while changed:
            changed = False
            new_paths = []
            for path in paths:
                last_block = path[-1]
                path_changed = False
                for succ in self.graph.successors(last_block):
                    if succ not in path and (self._is_ret2arg0_block(succ) or self._is_safe_block(succ)):
                        new_path = list(path) + [succ]
                        new_paths.append(new_path)
                        changed = True
                        path_changed = True
                    visited.add(succ)
                if not path_changed:
                    new_paths.append(path)
            paths = new_paths
        paths = set(tuple(path) for path in paths if isinstance(path[-1].statements[-1], Return))
        return paths

    def find_ret2arg0_paths(self, remove_phi=False):
        visited = set()
        paths = set()
        for block in GraphUtils.quasi_topological_sort_nodes(self.graph):
            if self._is_ret2arg0_block(block) and block not in visited:
                paths = paths.union(self._find_ret2arg0_path(block, visited))
            else:
                visited.add(block)
        paths = set(self._remove_phi(path) if remove_phi else path for path in paths)
        return paths

    @staticmethod
    def path_to_graph(path):
        graph = DiGraph()
        graph.add_node(path[0])
        for i in range(len(path) - 1):
            u = path[i]
            v = path[i + 1]
            graph.add_edge(u, v)
        return graph

    def find_backward_path(self, block, max_length=None):
        visited = {block}
        path = [block]
        try:
            while len(preds := list(self.graph.predecessors(block))) == 1 and (
                max_length is None or len(path) < max_length
            ):
                block = preds[0]
                if block in visited:
                    break
                visited.add(block)
                path.insert(0, block)
        except NetworkXError:
            pass
        return path

    def find_forward_path(self, block, max_length=None):
        visited = {block}
        path = [block]
        try:
            while len(succs := list(self.graph.successors(block))) == 1 and (
                max_length is None or len(path) < max_length
            ):
                block = succs[0]
                if block in visited:
                    break
                visited.add(block)
                path.append(block)
        except NetworkXError:
            pass
        return path
