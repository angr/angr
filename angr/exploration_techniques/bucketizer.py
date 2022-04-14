
import math
from collections import defaultdict
import logging

from ..engines.successors import SimSuccessors
from . import ExplorationTechnique

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)


class Bucketizer(ExplorationTechnique):
    """
    Loop bucketization: Pick log(n) paths out of n possible paths, and stash (or drop) everything else.
    """

    def __init__(self):

        super().__init__()

    def successors(self, simgr, state, **kwargs):

        # step first
        successors = super().successors(simgr, state, **kwargs)  # type: SimSuccessors

        # if there are more than one successor, we try to get rid of the ones that we don't want

        if len(successors.successors) <= 1:
            return successors

        new_successors = [ ]

        for succ in successors.successors:
            if succ.history.jumpkind != 'Ijk_Boring':
                new_successors.append(succ)
                continue
            # transition = (succ.callstack.func_addr, succ.history.addr, succ.addr)
            transition = succ.addr
            self._record_transition(succ, transition)

            if self._accept_transition(succ, transition):
                new_successors.append(succ)

        if len(new_successors) != len(successors.successors):
            _l.debug("Bucketizer: Dropped %d states out of %d.",
                     len(successors.successors) - len(new_successors),
                     len(successors.successors))

        successors.successors = new_successors
        return successors

    def _get_transition_dict(self, state):
        """

        :param SimState state:
        :return:
        """

        try:
            t = state.globals['transition']
        except KeyError:
            t = defaultdict(int)
            state.globals['transition'] = t
        return t

    def _record_transition(self, state, transition):
        """

        :param SimState state:
        :param tuple transition:
        :return:
        """

        t = self._get_transition_dict(state).copy()
        t[transition] += 1

        state.globals['transition'] = t

    def _accept_transition(self, state, transition):
        """

        :param SimState state:
        :param tuple transition:
        :return:
        """

        t = self._get_transition_dict(state)

        if t[transition] == 0:
            _l.error("Impossible: Transition %s has 0 occurrences.", transition)
            return True

        n = math.log2(t[transition])
        if n.is_integer():
            return True
        return False
