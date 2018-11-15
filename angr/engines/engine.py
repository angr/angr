import sys
import logging


l = logging.getLogger(name=__name__)


class SimEngine(object):
    """
    A SimEngine is a class which understands how to perform execution on a state. This is a base class.

    :cvar requires_project: True, if this engine requires a project to operate.
    """
    requires_project = True

    def __init__(self, project=None, *args, **kwargs):
        if project is None and self.requires_project:
            raise ValueError("%s requires project to operate" % self.__class__)
        self.project = project

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
        addr = state.solver.eval(state._ip) if force_addr is None else force_addr

        # make a copy of the initial state for actual processing, if needed
        if not inline and o.COPY_STATES in state.options:
            new_state = state.copy()
        else:
            new_state = state
        # enforce this distinction
        old_state = state
        del state

        # we have now officially begun the stepping process! now is where we "cycle" a state's
        # data - move the "present" into the "past" by pushing an entry on the history stack.
        # nuance: make sure to copy from the PREVIOUS state to the CURRENT one
        # to avoid creating a dead link in the history, messing up the statehierarchy
        if not inline:
            new_state.register_plugin('history', old_state.history.make_child())
        new_state.history.recent_bbl_addrs.append(addr)

        if not inline:
            new_state.scratch.clear()
            new_state.scratch.executed_pages_set = set()

        if new_state.scratch.executed_pages_set is None:
            new_state.scratch.executed_pages_set = set()

        new_state.scratch.executed_pages_set |= {addr & ~0xFFF}

        successors = self._empty_successors(addr, old_state)

        new_state._inspect('engine_process', when=BP_BEFORE, sim_engine=self, sim_successors=successors, address=addr)
        successors = new_state._inspect_getattr('sim_successors', successors)
        try:
            self._process(new_state, successors, *args, **kwargs)
        except SimException:
            if o.EXCEPTION_HANDLING not in old_state.options:
                raise
            old_state.project.simos.handle_exception(successors, self, *sys.exc_info())

        new_state._inspect('engine_process', when=BP_AFTER, sim_successors=successors, address=addr)
        successors = new_state._inspect_getattr('sim_successors', successors)

        # downsizing
        new_state.inspect.downsize()
        # if not TRACK, clear actions on OLD state
        #if o.TRACK_ACTION_HISTORY not in old_state.options:
        #    old_state.history.recent_events = []

        # fix up the descriptions...
        description = str(successors)
        l.info("Ticked state: %s", description)
        for succ in successors.all_successors:
            succ.history.recent_description = description
        for succ in successors.flat_successors:
            succ.history.recent_description = description

        return successors

    def check(self, state, *args, **kwargs):
        """
        Check if this engine can be used for execution on the current state. A callback `check_failure` is called upon
        failed checks. Note that the execution can still fail even if check() returns True.

        You should only override this method in a subclass in order to provide the correct method signature and
        docstring. You should override the ``_check`` method to do your actual execution.

        :param SimState state: The state with which to execute.
        :param args:                   Positional arguments that will be passed to process().
        :param kwargs:                 Keyword arguments that will be passed to process().
        :return:                       True if the state can be handled by the current engine, False otherwise.
        """

        return self._check(state, *args, **kwargs)

    def _check(self, state, *args, **kwargs):
        raise NotImplementedError()

    def _process(self, new_state, successors, *args, **kwargs):
        raise NotImplementedError

    def _empty_successors(self, addr, initial_state, *args, **kwargs):  # pylint:disable=unused-arguments
        return SimSuccessors(addr, initial_state)


from .. import sim_options as o
from ..state_plugins.inspect import BP_BEFORE, BP_AFTER
from .successors import SimSuccessors
from ..errors import SimException
