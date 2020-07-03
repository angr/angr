from ..errors import AngrExitError
from . import ExplorationTechnique

import logging
l = logging.getLogger(name=__name__)


class Slicecutor(ExplorationTechnique):
    """
    The Slicecutor is an exploration that executes provided code slices.
    """

    def __init__(self, annotated_cfg, force_taking_exit=False, force_sat: bool=False):
        """
        All parameters except `annotated_cfg` are optional.

        :param annotated_cfg:       The AnnotatedCFG that provides the code slice.
        :param force_taking_exit:   Set to True if you want to create a successor based on our slice in case of
                                    unconstrained successors.
        :param force_sat:           If a branch specified by the slice is unsatisfiable, set this option to True if you
                                    want to force it to be satisfiable and be taken anyway.
        """
        super(Slicecutor, self).__init__()

        self._annotated_cfg = annotated_cfg
        self._force_taking_exit = force_taking_exit
        self._force_sat = force_sat

    def setup(self, simgr):
        for stash in ('cut', 'mysteries'):
            simgr.populate(stash, [])

    def filter(self, simgr, state, **kwargs):
        l.debug("Checking state %s for filtering...", state)
        return simgr.filter(state, **kwargs)

    def step_state(self, simgr, state, **kwargs):
        l.debug("%s ticking state %s at address %#x.", self, state, state.addr)
        stashes = simgr.step_state(state, **kwargs)

        new_active = []
        new_cut = []
        new_mystery = []

        # SimulationManager returns new active states in the None stash by default.
        flat_successors = stashes.get(None, None)
        if flat_successors is None:
            # Did the user explicitly put them into the 'active' stash instead?
            flat_successors = stashes.pop('active', [])

        for successor in flat_successors:
            l.debug("... checking exit to %#x from %#x.", successor.addr, state.addr)

            try:
                taken = self._annotated_cfg.should_take_exit(state.addr, successor.addr)
            except AngrExitError: # TODO: which exception?
                l.debug("... annotated CFG did not know about it!")
                new_mystery.append(successor)
            else:
                if taken:
                    l.debug("... taking the exit.")
                    new_active.append(successor)
                    # the else case isn't here, because the state should set errored in this
                    # case and we'll catch it below
                else:
                    l.debug("... not taking the exit.")
                    new_cut.append(successor)

        unconstrained_successors = stashes.get('unconstrained', [])
        if not new_active and unconstrained_successors and self._force_taking_exit:
            stashes['unconstrained'] = []
            # somehow there is no feasible state. We are forced to create a successor based on our slice
            if len(unconstrained_successors) != 1:
                raise Exception("This should absolutely never happen, what?")
            for target in self._annotated_cfg.get_targets(state.addr):
                successor = unconstrained_successors[0].copy()
                successor.regs._ip = target
                new_active.append(successor)
            l.debug('Got unconstrained: %d new states are created based on AnnotatedCFG.', len(new_active))

        unsat_successors = stashes.get('unsat', None)
        if not new_active and unsat_successors and self._force_sat:
            stashes['unsat'] = []
            # find the state
            targets = self._annotated_cfg.get_targets(state.addr)
            if targets is None:
                targets = [ ]
            for target in targets:
                try:
                    suc = next(iter(u for u in unsat_successors if u.addr == target))
                except StopIteration:
                    continue

                # drop all constraints
                if suc.mode == "fastpath":
                    # dropping constraints and making the state satisfiable again under fastpath mode is easy
                    suc.solver._solver.constraints = [ ]
                    suc._satisfiable = True
                    new_active.append(suc)
                    l.debug("Forced unsat at %#x to be sat again.", suc.addr)
                else:
                    # with multiple possible solver frontends, dropping states in other state modes is not
                    # straightforward. I'll leave it to the next person who uses this feature
                    l.warning("force_sat is not implemented for solver mode %s.", suc.moe)


        stashes[None] = new_active
        stashes['mystery'] = new_mystery
        stashes['cut'] = new_cut
        return stashes

    def successors(self, simgr, state, **kwargs):
        kwargs['whitelist'] = self._annotated_cfg.get_whitelisted_statements(state.addr)
        kwargs['last_stmt'] = self._annotated_cfg.get_last_statement_index(state.addr)
        return simgr.successors(state, **kwargs)
