import logging

from . import ExplorationTechnique
from .. import BP_AFTER, BP_BEFORE


l = logging.getLogger("angr.exploration_techniques.crash_monitor")


EXEC_STACK = 'EXEC_STACK'
QEMU_CRASH = 'SEG_FAULT'


class CrashMonitor(ExplorationTechnique):
    """
    An exploration technique that checks for crashing (currently only during tracing).

    The crashed state that would make the program crash is in 'crashed' stash.
    """

    def __init__(self, trace=None, crash_addr=None):
        """
        :param trace       : The basic block trace.
        :param crash_addr  : If the input caused a crash, what address did it crash at?
        """

        super(CrashMonitor, self).__init__()
        # TODO add concolic mode to this and tracer
        # ^ what r u talking about, tracer+preconstrainer is literally an implementation of concolic execution
        self._trace = trace
        self._crash_addr = crash_addr

        self.last_state = None
        self._crash_type = None
        self._crash_state = None

    # TODO NEXT STEP: move all functionality into a filter hook. make complete very simple.
    # maybe not filter?? that won't see the "traced" state...
    # what would it take to make this not be an explortation technique? an analysis for instance?
    def complete(self, simgr):
        # if we spot a crashed state, return the goods >:]
        if self._crash_type is not None:
            if self._crash_type == QEMU_CRASH:
                # time to recover the crashing state
                self._crash_state = self._crash_windup()
                l.debug("Found the crash!")

            simgr.populate('crashed', [self._crash_state])
            return True

        return False

    def step(self, simgr, stash='active', **kwargs):
        if len(simgr.active) == 1:
            self.last_state = simgr.active[0]

            simgr.step(stash=stash, **kwargs)
            for state in simgr.stashes[stash]:
                self._check_stack(state)

            if self._crash_type == EXEC_STACK:
                return simgr

            # check to see if we reached a deadend
            if self.last_state.globals['trace_idx'] >= len(self._trace) - 1:
                simgr.step(stash=stash)
                self._crash_type = QEMU_CRASH
                return simgr

        return simgr

    def _check_stack(self, state):
        if state.memory.load(state.ip, state.ip.length).symbolic:
            l.debug("executing input-related code")
            self._crash_type = EXEC_STACK
            self._crash_state = state

    def _crash_windup(self):
        # before we step through and collect the actions we have to set
        # up a special case for address concretization in the case of a
        # controlled read or write vulnerability.
        state = self.last_state

        bp1 = state.inspect.b(
            'address_concretization',
            BP_BEFORE,
            action=self._dont_add_constraints)

        bp2 = state.inspect.b(
            'address_concretization',
            BP_AFTER,
            action=self._grab_concretization_results)

        # step to the end of the crashing basic block,
        # to capture its actions with those breakpoints
        state.step()

        # Add the constraints from concretized addrs back
        for var, concrete_vals in state.preconstrainer.address_concretization:
            if len(concrete_vals) > 0:
                l.debug("constraining addr to be %#x", concrete_vals[0])
                state.add_constraints(var == concrete_vals[0])

        # then we step again up to the crashing instruction
        inst_addrs = state.block().instruction_addrs
        inst_cnt = len(inst_addrs)

        if inst_cnt == 0:
            insts = 0
        elif self._crash_addr in inst_addrs:
            insts = inst_addrs.index(self._crash_addr) + 1
        else:
            insts = inst_cnt - 1

        succs = state.step(num_inst=insts).flat_successors

        if len(succs) > 0:
            if len(succs) > 1:
                succs = [s for s in succs if s.solver.satisfiable()]
            state = succs[0]
            self.last_state = state

        # remove the preconstraints
        l.debug("removing preconstraints")
        state.preconstrainer.remove_preconstraints()

        l.debug("reconstraining... ")
        state.preconstrainer.reconstrain()

        # now remove our breakpoints since other people might not want them
        state.inspect.remove_breakpoint("address_concretization", bp1)
        state.inspect.remove_breakpoint("address_concretization", bp2)

        l.debug("final step...")
        succs = state.step()
        successors = succs.flat_successors + succs.unconstrained_successors
        return successors[0]

    # the below are utility functions for crash windup

    def _grab_concretization_results(self, state):
        """
        Grabs the concretized result so we can add the constraint ourselves.
        """
        # only grab ones that match the constrained addrs
        if self._add_constraints(state):
            addr = state.inspect.address_concretization_expr
            result = state.inspect.address_concretization_result
            if result is None:
                l.warning("addr concretization result is None")
                return
            state.preconstrainer.address_concretization.append((addr, result))

    def _dont_add_constraints(self, state):
        """
        Obnoxious way to handle this, should ONLY be called from crash monitor.
        """
        # for each constrained addrs check to see if the variables match,
        # if so keep the constraints
        state.inspect.address_concretization_add_constraints = self._add_constraints(state)

    def _add_constraints(self, state):
        variables = state.inspect.address_concretization_expr.variables
        hit_indices = CrashMonitor._to_indices(variables)

        for action in state.preconstrainer._constrained_addrs:
            var_indices = self._to_indices(action.addr.variables)
            if var_indices == hit_indices:
                return True
        return False

    @staticmethod
    def _to_indices(variables):
        variables = [v for v in variables if v.startswith("file_/dev/stdin")]
        indices = map(lambda y: int(y.split("_")[3], 16), variables)
        return sorted(indices)
