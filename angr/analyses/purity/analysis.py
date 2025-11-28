from __future__ import annotations

from angr import ailment
from angr.analyses import Analysis
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.forward_analysis.forward_analysis import ForwardAnalysisForClinic
from angr.knowledge_plugins.functions.function import Function
from .engine import PurityEngineAIL, ResultType, StateType


class AILPurityAnalysis(Analysis, ForwardAnalysisForClinic[StateType]):
    """
    Determined how data sources are used in a given function.
    """

    def __init__(
        self,
        subject: str | int | Function | Clinic,
    ):
        if isinstance(subject, (str, int)):
            subject = self.kb.functions[subject]
        if isinstance(subject, Function):
            subject = self.project.analyses.Clinic(subject)
        self.engine = PurityEngineAIL(self.project, subject)
        self.result = ResultType()
        ForwardAnalysisForClinic.__init__(self, allow_merging=True, clinic=subject)

        self._analyze()

    def _initial_abstract_state(self, node: ailment.Block) -> StateType:
        return self.engine.initial_state(node)

    def _step_node(self, node, state: StateType) -> tuple[bool | None, StateType]:
        state = state.copy()
        state.addr = (node.addr, node.idx)
        result = self.engine.process(state, block=node)
        self.result.update(result)
        return None, state

    def _handle_phi(self, node, succ, state, dst_vvar, src_vvar):
        state.vars[dst_vvar.varid] |= state.vars[src_vvar.varid]

    def _merge_states(self, node, *states) -> tuple[StateType, bool]:
        changed = False
        result = states[0]
        for state in states[1:]:
            for varid, val in state.vars.items():
                oval = result.vars[varid]
                if val - oval:
                    changed = True
                    oval |= val

        assert self.engine.clinic.graph is not None
        return result, changed

    def _compare_states(self, node, old_state, new_state) -> bool:
        return old_state.vars == new_state.vars
