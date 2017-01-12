import logging

l = logging.getLogger('simuvex.engines.engine')


class SimEngine(object):
    """
    How to actually execute stuff.
    Abstracts over VEX, Python (simprocedures), Unicorn, LLVM, and hopefully more in the future.

    :ivar callable check_failed: A callback that is called after _check() returns False.
    """

    def __init__(self, check_failed=None):
        self._check_failed = check_failed

    def process(self, new_state, *args, **kwargs):
        """
        Perform execution with a state.

        :param new_state:   The state with which to execute. This state will be modified during execution.
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the execution's successor states
        """
        inline = kwargs.pop('inline', False)
        force_addr = kwargs.pop('force_addr', None)
        addr = new_state.se.any_int(new_state.ip) if force_addr is None else force_addr

        # clear the log (unless we're inlining)
        if not inline:
            new_state.log.clear()
            new_state.scratch.clear()
            new_state.scratch.bbl_addr = addr

        successors = SimSuccessors(addr, new_state)
        self._process(new_state, successors, *args, **kwargs)
        return successors

    def check(self, state, *args, **kwargs):
        """
        Check if this engine can be used for execution on the current state. A callback `check_failure` is called upon
        failed checks. Note that the execution can still fail even if check() returns True.

        :param simuvex.SimState state: The state with which to execute.
        :param args:                   Positional arguments that will be passed to process().
        :param kwargs:                 Keyword arguments that will be passed to process().
        :return:                       True if the state can be handled by the current engine, False otherwise.
        """

        r = self._check(state, *args, **kwargs)

        if not r:
            if self._check_failed is not None:
                self._check_failed(state, *args, **kwargs)

        return r

    def _check(self, state, *args, **kwargs):
        raise NotImplementedError()

    def _process(self, new_state, successors, *args, **kwargs):
        raise NotImplementedError

from simuvex import s_options as o
from .successors import SimSuccessors
