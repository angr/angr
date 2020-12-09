from typing import Optional, List, TYPE_CHECKING

import networkx

import claripy

from ...state_plugins.inspect import BP_BEFORE, BP
from ..analysis import Analysis, AnalysesHub

if TYPE_CHECKING:
    from angr import SimState
    from angr.knowledge_plugins.functions import Function
    from .abstract_state import AbstractStateFields


class StateGraphRecoveryAnalysis(Analysis):
    """
    Traverses a function and derive a state graph with respect to given variables.
    """
    def __init__(self, func: 'Function', fields: 'AbstractStateFields', init_state: Optional['SimState']=None):
        self.func = func
        self.fields = fields
        self.init_state = init_state
        self._ret_trap: int = 0x1f37ff4a

        self._tv_sec_var = None
        self._tv_nsec_var = None
        self.state_graph = None

        self.traverse()

    def traverse(self):

        # create an empty state graph
        self.state_graph = networkx.DiGraph()

        # make the initial state
        init_state = self._initialize_state(init_state=self.init_state)
        self._symbolize_timecounter(init_state)
        self._install_constraint_hook(init_state)
        abs_state = self.fields.generate_abstract_state(init_state)
        self.state_graph.add_node(abs_state)
        state_queue = [(init_state, abs_state, None)]

        while state_queue:
            prev_state, prev_abs_state, time_delta = state_queue.pop(0)
            if time_delta is None:
                pass
            else:
                # advance the time stamp as required
                self._advance_timecounter(prev_state, time_delta)

            # symbolically trace the state
            next_state = self._traverse_one(prev_state)

            print(time_delta)
            abs_state = self.fields.generate_abstract_state(next_state)
            abs_state += (('time_delta', time_delta),)
            print(abs_state)

            self.state_graph.add_edge(prev_abs_state, abs_state, time_delta=time_delta)

            # discover time deltas
            deltas = self._discover_time_deltas(next_state)
            print("New deltas", deltas)
            if deltas:
                for delta in deltas:
                    new_state = self._initialize_state(init_state=next_state)
                    state_queue.append((new_state, abs_state, delta))
            else:
                if prev_abs_state == abs_state and time_delta is None:
                    continue
                new_state = self._initialize_state(init_state=next_state)
                state_queue.append((new_state, abs_state, None))

    def _discover_time_deltas(self, state: 'SimState') -> List[int]:
        state = self._initialize_state(state)
        time_deltas = self._symbolically_advance_timecounter(state)
        next_state = self._traverse_one(state)

        # detect required time delta
        # TODO: Extend it to more than just seconds
        steps: List[int] = [ ]
        if time_deltas:
            for delta in time_deltas:
                for constraint in next_state.solver.constraints:
                    if constraint.op == "__eq__" and constraint.args[0] is delta:
                        continue
                    elif constraint.op == "__ne__" and constraint.args[0] is delta:
                        # found a potential step
                        if constraint.args[1].op == 'BVV':
                            step = constraint.args[1].args[0]
                            steps.append(step)

        return steps

    def _symbolize_timecounter(self, state: 'SimState') -> None:
        # TODO: Generalize it
        tv_sec_addr = 0x425620
        tv_nsec_addr = tv_sec_addr + 8

        self._tv_sec_var = claripy.BVS('tv_sec', 64)
        self._tv_nsec_var = claripy.BVS('tv_nsec', 64)

        state.memory.store(tv_sec_addr, self._tv_sec_var, endness=self.project.arch.memory_endness)
        state.memory.store(tv_nsec_addr, self._tv_nsec_var, endness=self.project.arch.memory_endness)

        # the initial timer values are 0
        state.preconstrainer.preconstrain(claripy.BVV(0, 64), self._tv_sec_var)
        state.preconstrainer.preconstrain(claripy.BVV(0, 64), self._tv_nsec_var)

    def _symbolically_advance_timecounter(self, state: 'SimState') -> List[claripy.ast.Bits]:
        # TODO: Generalize it
        sec_delta = claripy.BVS("sec_delta", 64)
        state.preconstrainer.preconstrain(claripy.BVV(1, 64), sec_delta)

        tv_sec = state.memory.load(0x425620, size=8, endness=self.project.arch.memory_endness)
        state.memory.store(0x425620, tv_sec + sec_delta, endness=self.project.arch.memory_endness)

        return [sec_delta]

    def _advance_timecounter(self, state: 'SimState', delta: int) -> None:
        # TODO: Generalize it
        tv_sec = state.memory.load(0x425620, size=8, endness=self.project.arch.memory_endness)
        state.memory.store(0x425620, tv_sec + delta, endness=self.project.arch.memory_endness)

        # hack
        tv_nsec = state.memory.load(0x425620 + 8, size=8, endness=self.project.arch.memory_endness)
        state.memory.store(0x425620 + 8, tv_nsec + 200, endness=self.project.arch.memory_endness)

    def _traverse_one(self, state: 'SimState'):

        simgr = self.project.factory.simgr(state)

        while simgr.active:
            # print(simgr.active)
            # import sys
            # sys.stdout.write('.')

            s = simgr.active[0]

            simgr.stash(lambda x: x.addr == self._ret_trap, from_stash='active', to_stash='finished')

            simgr.step()

        # import sys
        # sys.stdout.write('\n')
        assert len(simgr.finished) == 1

        return simgr.finished[0]

    def _initialize_state(self, init_state=None) -> 'SimState':
        if init_state is not None:
            s = init_state.copy()
            s.ip = self.func.addr
        else:
            s = self.project.factory.blank_state(addr=self.func.addr)
            s.regs.rdi = 0xc0000000
            s.memory.store(0xc0000000, b"\x00" * 0x1000)

        if self.project.arch.call_pushes_ret:
            s.stack_push(claripy.BVV(self._ret_trap, self.project.arch.bits))
        else:
            # TODO: set up the link register or the return address
            pass

        return s

    def _install_constraint_hook(self, state: 'SimState') -> None:
        bp = BP(when=BP_BEFORE, enabled=True, action=self._log_constraint)
        state.inspect.add_breakpoint('constraints', bp)

    def _log_constraint(self, state):
        constraints = state.inspect.added_constraints
        if len(constraints) == 1 and (claripy.is_true(constraints[0]) or claripy.is_false(constraints[0])):
            return
        # import ipdb; ipdb.set_trace()


AnalysesHub.register_default('StateGraphRecovery', StateGraphRecoveryAnalysis)
