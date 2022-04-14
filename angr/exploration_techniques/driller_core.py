import logging
from itertools import islice

from . import ExplorationTechnique


l = logging.getLogger(name=__name__)


class DrillerCore(ExplorationTechnique):
    """
    An exploration technique that symbolically follows an input looking for new
    state transitions.

    It has to be used with Tracer exploration technique. Results are put in
    'diverted' stash.
    """

    def __init__(self, trace, fuzz_bitmap=None):
        """
        :param trace      : The basic block trace.
        :param fuzz_bitmap: AFL's bitmap of state transitions. Defaults to saying every transition is worth satisfying.
        """

        super(DrillerCore, self).__init__()
        self.trace = trace
        self.fuzz_bitmap = fuzz_bitmap or b"\xff" * 65536

        # Set of encountered basic block transitions.
        self.encounters = set()

    def setup(self, simgr):
        self.project = simgr._project

        # Update encounters with known state transitions.
        self.encounters.update(zip(self.trace, islice(self.trace, 1, None)))

    def step(self, simgr, stash='active', **kwargs):
        simgr.step(stash=stash, **kwargs)

        # Mimic AFL's indexing scheme.
        if 'missed' in simgr.stashes and simgr.missed:
            # A bit ugly, might be replaced by tracer.predecessors[-1] or crash_monitor.last_state.
            prev_addr = simgr.one_missed.history.bbl_addrs[-1]
            prev_loc = prev_addr
            prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
            prev_loc &= len(self.fuzz_bitmap) - 1
            prev_loc = prev_loc >> 1

            for state in simgr.missed:
                cur_loc = state.addr
                cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
                cur_loc &= len(self.fuzz_bitmap) - 1

                hit = bool(self.fuzz_bitmap[cur_loc ^ prev_loc] ^ 0xff)

                transition = (prev_addr, state.addr)
                mapped_to = self.project.loader.find_object_containing(state.addr).binary

                l.debug("Found %#x -> %#x transition.", transition[0], transition[1])

                if not hit and transition not in self.encounters and not self._has_false(state) and mapped_to != 'cle##externs':
                    state.preconstrainer.remove_preconstraints()

                    if state.satisfiable():
                        # A completely new state transition.
                        l.debug("Found a completely new transition, putting into 'diverted' stash.")
                        simgr.stashes['diverted'].append(state)
                        self.encounters.add(transition)

                    else:
                        l.debug("State at %#x is not satisfiable.", transition[1])

                elif self._has_false(state):
                    l.debug("State at %#x is not satisfiable even remove preconstraints.", transition[1])

                else:
                    l.debug("%#x -> %#x transition has already been encountered.", transition[0], transition[1])

        return simgr

    #
    # Private methods
    #

    @staticmethod
    def _has_false(state):
        # Check if the state is unsat even if we remove preconstraints.
        claripy_false = state.solver.false
        if state.scratch.guard.cache_key == claripy_false.cache_key:
            return True

        for c in state.solver.constraints:
            if c.cache_key == claripy_false.cache_key:
                return True

        return False
