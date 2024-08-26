from collections import defaultdict
from typing import Optional, Dict

from ailment import Expression, Block
from ailment.expression import BasePointerOffset
from ailment.statement import Call, Store

from angr.analyses import Analysis, AnalysesHub
from angr.utils.graph import GraphUtils


class SimpleReachingDefinitionsState:
    def __init__(self):
        self.reg_defs = {}
        self.stack_defs = {}

    def add_reg_def(self, base, offset, expr):
        pass

    def add_stack_def(self, offset, expr):
        self.stack_defs[offset] = expr

    def get_reg_def(self, base, offset) -> Optional[Expression]:
        pass

    def get_stack_def(self, offset) -> Optional[Expression]:
        pass

    def copy(self):
        state = SimpleReachingDefinitionsState()
        state.reg_defs = state.reg_defs.copy()
        state.stack_defs = state.stack_defs.copy()
        return state

    def merge(self, other) -> "SimpleReachingDefinitionsState":
        return self


class SimpleReachingDefinitionsAnalysis(Analysis):
    def __init__(self, func, graph):
        self._func = func
        self._graph = graph

        self.in_states: Dict[Block, SimpleReachingDefinitionsState] = {}
        self.observation_results: Dict[Call, SimpleReachingDefinitionsState] = {}

        self._analyze()

    def _run_on_node(self, block, state) -> SimpleReachingDefinitionsState:
        state = state.copy()
        for stmt in block.statements:
            if isinstance(stmt, Store):
                if isinstance(stmt.addr, BasePointerOffset):
                    state.add_stack_def(stmt.addr.offset, stmt.data)
            elif isinstance(stmt, Call):
                self.observation_results[stmt] = state
        return state

    def _analyze(self):
        # Initialize state for each block
        for block in self._graph.nodes():
            self.in_states[block] = SimpleReachingDefinitionsState()

        queue = GraphUtils.quasi_topological_sort_nodes(self._graph, self._graph.nodes)
        iterations = defaultdict(int)
        while queue:
            block = queue.pop(0)
            if iterations[block] >= 2:
                continue
            iterations[block] += 1
            state = self.in_states[block]
            out_state = self._run_on_node(block, state)
            for succ in self._graph.successors(block):
                old_state = self.in_states[succ]
                new_state = old_state.merge(out_state)
                if old_state != new_state:
                    queue.append(succ)
                    self.in_states[succ] = new_state


AnalysesHub.register_default("SimpleReachingDefinitions", SimpleReachingDefinitionsAnalysis)
