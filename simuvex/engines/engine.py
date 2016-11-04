import logging

l = logging.getLogger('simuvex.engines.engine')


class SimEngine(object):
    """
    How to actually execute stuff.
    Abstracts over VEX, Python (simprocedures), Unicorn, LLVM, and hopefully more in the future.
    """

    def process(self, state, *args, **kwargs):
        """
        Perform execution with a state.

        :param state:       The state with which to execute
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the execution's successor states
        """
        inline = kwargs.pop('inline', False)
        force_addr = kwargs.pop('force_addr', None)
        addr = state.se.any_int(state.ip) if force_addr is None else force_addr

        # make a copy of the initial state for actual processing, if needed
        if not inline and o.COW_STATES in state.options:
            new_state = state.copy()
        else:
            new_state = state

        # clear the log (unless we're inlining)
        if not inline:
            new_state.log.clear()
            new_state.scratch.clear()
            new_state.scratch.bbl_addr = addr

        successors = SimSuccessors(addr)
        self._process(new_state, successors, *args, **kwargs)
        return successors

    def _process(self, new_state, successors, *args, **kwargs):
        raise NotImplementedError

from simuvex import s_options as o
from .successors import SimSuccessors
