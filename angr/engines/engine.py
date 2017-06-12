import logging

l = logging.getLogger('simuvex.engines.engine')


class SimEngine(object):
    """
    A SimEngine is a class which understands how to perform execution on a state. This is a base class.
    """

    def __init__(self, **kwargs):
        self._check_failed = kwargs.get('check_failed')

    def process(self, state, *args, **kwargs):
        """
        Perform execution with a state.

        You should only override this method in a subclass in order to provide the correct method signature and
        docstring. You should override the ``_process`` method to do your actual execution.

        :param state:       The state with which to execute. This state will be copied before
                            modification.
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the execution's successor states
        """
        inline = kwargs.pop('inline', False)
        force_addr = kwargs.pop('force_addr', None)
        addr = state.se.any_int(state._ip) if force_addr is None else force_addr

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

        successors = SimSuccessors(addr, state)
        self._process(new_state, successors, *args, **kwargs)
        return successors

    def check(self, state, *args, **kwargs):
        """
        Check if this engine can be used for execution on the current state. A callback `check_failure` is called upon
        failed checks. Note that the execution can still fail even if check() returns True.

        You should only override this method in a subclass in order to provide the correct method signature and
        docstring. You should override the ``_check`` method to do your actual execution.

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

    #
    # Pickling
    #

    # CPython cannot pickle methods, which is why we have special handlers here to avoid pickling callback registered
    # with SimEngine.

    def __setstate__(self, state):
        self._check_failed = None

    def __getstate__(self):
        return { }

from simuvex import s_options as o
from .successors import SimSuccessors
