# pylint:disable=unused-import,missing-class-docstring,wrong-import-position
import angr  # For type annotations


class ExplorationTechnique:
    """
    An otiegnqwvk is a set of hooks for a simulation manager that assists in the implementation of new techniques in
    symbolic exploration.

    TODO: choose actual name for the functionality (techniques? strategies?)

    Any number of these methods may be overridden by a subclass.
    To use an exploration technique, call ``simgr.use_technique`` with an *instance* of the technique.
    """

    # this is the master list of hook functinos
    _hook_list = ("step", "filter", "selector", "step_state", "successors")

    def _get_hooks(self):
        return {name: getattr(self, name) for name in self._hook_list if self._is_overriden(name)}

    def _is_overriden(self, name):
        return getattr(self, name).__code__ is not getattr(ExplorationTechnique, name).__code__

    def __init__(self):
        # this attribute will be set from above by the manager
        if not hasattr(self, "project"):
            self.project: angr.project.Project = None

    def setup(self, simgr):
        """
        Perform any initialization on this manager you might need to do.

        :param angr.SimulationManager simgr:    The simulation manager to which you have just been added
        """

    def step(self, simgr, stash="active", **kwargs):  # pylint:disable=no-self-use
        """
        Hook the process of stepping a stash forward. Should call ``simgr.step(stash, **kwargs)`` in order to do the
        actual processing.

        :param angr.SimulationManager simgr:
        :param str stash:
        """
        simgr.step(stash=stash, **kwargs)

    def filter(self, simgr, state, **kwargs):  # pylint:disable=no-self-use
        """
        Perform filtering on which stash a state should be inserted into.

        If the state should be filtered, return the name of the stash to move the state to.
        If you want to modify the state before filtering it, return a tuple of the stash to move the state to and the
        modified state.
        To defer to the original categorization procedure, return the result of ``simgr.filter(state, **kwargs)``

        If the user provided a ``filter_func`` in their step or run command, it will appear here.

        :param angr.SimulationManager simgr:
        :param angr.SimState state:
        """
        return simgr.filter(state, **kwargs)

    def selector(self, simgr, state, **kwargs):  # pylint:disable=no-self-use
        """
        Determine if a state should participate in the current round of stepping.
        Return True if the state should be stepped, and False if the state should not be stepped.
        To defer to the original selection procedure, return the result of ``simgr.selector(state, **kwargs)``.

        If the user provided a ``selector_func`` in their step or run command, it will appear here.

        :param angr.SimulationManager simgr:
        :param angr.SimState state:
        """
        return simgr.selector(state, **kwargs)

    def step_state(self, simgr, state, **kwargs):  # pylint:disable=no-self-use
        """
        Determine the categorization of state successors into stashes. The result should be a dict mapping stash names
        to the list of successor states that fall into that stash, or None as a stash name to use the original stash
        name.

        If you would like to directly work with a `SimSuccessors` object, you can obtain it with
        ``simgr.successors(state, **kwargs)``. This is not recommended, as it denies other hooks the opportunity to
        look at the successors. Therefore, the usual technique is to call ``simgr.step_state(state, **kwargs)`` and
        then mutate the returned dict before returning it yourself.

        ..note:: This takes precedence over the `filter` hook - `filter` is only applied to states returned from here
        in the None stash.

        :param angr.SimulationManager simgr:
        :param angr.SimState state:
        """
        return simgr.step_state(state, **kwargs)

    def successors(self, simgr, state, **kwargs):  # pylint:disable=no-self-use
        """
        Perform the process of stepping a state forward, returning a SimSuccessors object.

        To defer to the original succession procedure, return the result of ``simgr.successors(state, **kwargs)``.
        Be careful about not calling this method (e.g. calling ``project.factory.successors`` manually) as it denies
        other hooks the opportunity to instrument the step. Instead, you can mutate the kwargs for the step before
        calling the original, and mutate the result before returning it yourself.

        If the user provided a ``successor_func`` in their step or run command, it will appear here.

        :param angr.SimulationManager simgr:
        :param angr.SimState state:
        """
        return simgr.successors(state, **kwargs)

    def complete(self, simgr):  # pylint:disable=no-self-use,unused-argument
        """
        Return whether or not this manager has reached a "completed" state, i.e. ``SimulationManager.run()`` should
        halt.

        This is the one hook which is *not* subject to the nesting rules of hooks.
        You should *not* call ``simgr.complete``, you should make your own decision and return True or False.
        Each of the techniques' completion checkers will be called and the final result will be compted with
        ``simgr.completion_mode``.

        :param angr.SimulationManager simgr:
        """
        return False


from .slicecutor import Slicecutor
from .driller_core import DrillerCore
from .loop_seer import LoopSeer
from .tracer import Tracer
from .explorer import Explorer
from .threading import Threading
from .dfs import DFS
from .lengthlimiter import LengthLimiter
from .veritesting import Veritesting
from .oppologist import Oppologist
from .director import Director, ExecuteAddressGoal, CallFunctionGoal
from .spiller import Spiller
from .manual_mergepoint import ManualMergepoint
from .tech_builder import TechniqueBuilder
from .stochastic import StochasticSearch
from .unique import UniqueSearch
from .symbion import Symbion
from ..errors import AngrError, AngrExplorationTechniqueError
from .memory_watcher import MemoryWatcher
from .bucketizer import Bucketizer
from .local_loop_seer import LocalLoopSeer
from .timeout import Timeout
from .suggestions import Suggestions

__all__ = (
    "ExplorationTechnique",
    "Slicecutor",
    "DrillerCore",
    "LoopSeer",
    "Tracer",
    "Explorer",
    "Threading",
    "DFS",
    "LengthLimiter",
    "Veritesting",
    "Oppologist",
    "Director",
    "ExecuteAddressGoal",
    "CallFunctionGoal",
    "Spiller",
    "ManualMergepoint",
    "TechniqueBuilder",
    "StochasticSearch",
    "UniqueSearch",
    "Symbion",
    "MemoryWatcher",
    "Bucketizer",
    "LocalLoopSeer",
    "Timeout",
    "Suggestions",
)
