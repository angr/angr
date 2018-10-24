from collections import defaultdict

from ..errors import AngrExitError
from ..sim_manager import SimulationManager
from . import ExplorationTechnique

import logging
l = logging.getLogger(name=__name__)


class Slicecutor(ExplorationTechnique):
    """
    The Slicecutor is an exploration that executes provided code slices.
    """

    def __init__(self, annotated_cfg, targets=None, max_concurrency=None, max_active=None,
                 max_loop_iterations=None, pickle_paths=None, merge_countdown=10, force_taking_exit=False,
                 suspend_states=True):
        """
        All parameters except `annotated_cfg` are optional.

        :param annotated_cfg:       The AnnotatedCFG that provides the code slice.
        :param targets:             A list of (bbl_addr, stmt_idx) tuples that specify where to stop
                                    the execution.
        :param max_concurrency:     NOT IMPLEMENTED
        :param max_active:          The maximum number of states to keep in active stash.
        :param max_loop_iterations: The loop limiter.
        :param pickle_paths:        NOT IMPLEMENTED
        :param merge_countdown:     TODO: This seems to have no effect.
        :param force_taking_exit:   True, if you want to create a successor based on our slice if other
                                    successors are unfeasible.
        :param suspend_states:      True, if you want to downsize states that are not currently active.
        """
        super(Slicecutor, self).__init__()

        if max_concurrency is not None:
            l.warning("max_concurrency is not implemented")

        if pickle_paths is not None:
            l.warning("pickle_paths is not implemented")

        self._annotated_cfg = annotated_cfg

        self._max_loop_iterations = max_loop_iterations or None
        self._max_active = max_active or 0

        self._suspend_states = suspend_states
        self._force_taking_exit = force_taking_exit

        self._targets = targets if targets is not None else []

        self._merge_candidates = defaultdict(list)
        self._merge_countdowns = { }
        self.merge_countdown = merge_countdown

    def setup(self, simgr):
        for stash in ('cut', 'mysteries', 'reached_targets'):
            simgr.populate(stash, [])

    def step(self, simgr, stash='active', **kwargs):  # pylint:disable=no-self-use
        for addr in list(self._merge_countdowns):
            if self._merge_countdowns[addr] > 0:
                self._merge_countdowns[addr] -= 1
                continue

            _ = self._merge_countdowns.pop(addr)
            to_merge = self._merge_candidates.pop(addr)
            l.debug("... merging %d states!", len(to_merge))

            if len(to_merge) > 1:
                new_state = to_merge[0].merge(*(to_merge[1:]))
            else:
                new_state = to_merge[0]

            new_state.extra_length += self.merge_countdown
            simgr.populate('active', [new_state])

        simgr.split(state_ranker=self.state_key, limit=self._max_active, to_stash='active')
        return simgr.step(stash=stash, **kwargs)

    def filter(self, simgr, state, **kwargs):
        if state.addr in self._targets:
            return 'reached_targets', self.suspend_state(state)

        l.debug("Checking state %s for filtering...", state)
        if not self._annotated_cfg.filter_path(state):
            l.debug("... %s is cut by AnnoCFG explicitly.", state)
            return 'cut', self.suspend_state(state)

        l.debug("... checking loop iteration limit")
        if self._max_loop_iterations is not None and state.detect_loops() > self._max_loop_iterations:
            l.debug("... limit reached")
            return SimulationManager.DROP

        return simgr.filter(state, **kwargs)

    def step_state(self, simgr, state, **kwargs):
        l.debug("%s ticking state %s at address %#x.", self, state, state.addr)
        stashes = simgr.step_state(state, **kwargs)

        cut = False
        mystery = False
        new_active = []

        # SimulationManager returns new active states in the None stash by default.
        flat_successors = stashes.get(None, None)
        if flat_successors is None:
            # Did the user explicitly put them into the 'active' stash instead?
            flat_successors = stashes.get('active', [])

        for successor in flat_successors:
            l.debug("... checking exit to %#x from %#x.", successor.addr, state.addr)

            try:
                taken = self._annotated_cfg.should_take_exit(state.addr, successor.addr)
            except AngrExitError: # TODO: which exception?
                l.debug("... annotated CFG did not know about it!")
                mystery = True
                continue

            if taken:
                l.debug("... taking the exit.")
                new_active.append(successor)
                # the else case isn't here, because the state should set errored in this
                # case and we'll catch it below
            else:
                l.debug("... not taking the exit.")
                cut = True

        unconstrained_successors = stashes.get('unconstrained', [])
        if not new_active and unconstrained_successors and self._force_taking_exit:
            # somehow there is no feasible state. We are forced to create a successor based on our slice
            for target in self._annotated_cfg.get_targets(state.addr):
                successor = unconstrained_successors[0].copy()
                successor.regs._ip = target
                new_active.append(successor)
            l.debug('%d new states are created based on AnnotatedCFG.', len(new_active))

        return {'active': new_active,
                'mystery': [state] if mystery else [],
                'cut': [state] if cut else []}

    def successors(self, simgr, state, **kwargs):
        kwargs['whitelist'] = self._annotated_cfg.get_whitelisted_statements(state.addr)
        kwargs['last_stmt'] = self._annotated_cfg.get_last_statement_index(state.addr)
        return simgr.successors(state, **kwargs)

    def complete(self, simgr):  # pylint:disable=no-self-use,unused-argument
        return (len(simgr.active) + len(self._merge_countdowns)) == 0

    @staticmethod
    def state_key(a):
        if a.history.depth > 0:
            a_len = a.history.bbl_addrs.hardcopy.count(a.history.bbl_addrs[-1])
            return a.history.block_count, a_len
        return a.history.block_count, 0

    def suspend_state(self, state): #pylint:disable=no-self-use
        """
        Suspends and returns a state.

        :param state: the state
        :returns: the state
        """
        if self._suspend_states:
            # TODO: Path doesn't provide suspend() now. What should we replace it with?
            # p.suspend(do_pickle=self._pickle_paths)
            # TODO: that todo was from... at least 3 or 4 refactors ago, what is this supposed to do
            state.downsize()
        return state
