from .. import engines
from ..errors import SimError


# 8<----------------- Compatibility layer -----------------
class ExplorationTechniqueMeta(type):

    def __new__(mcs, name, bases, attrs):
        import inspect
        if name != 'ExplorationTechniqueCompat':
            if 'step' in attrs and not inspect.getargspec(attrs['step'])[3]:
                attrs['step'] = mcs._step_factory(attrs['step'])
            if 'filter' in attrs and inspect.getargspec(attrs['filter'])[0][1] != 'simgr':
                attrs['filter'] = mcs._filter_factory(attrs['filter'])
            if 'step_state' in attrs and inspect.getargspec(attrs['step_state'])[0][1] != 'simgr':
                attrs['step_state'] = mcs._step_state_factory(attrs['step_state'])
        return type.__new__(mcs, name, bases, attrs)

    @staticmethod
    def _step_factory(step):
        def step_wrapped(self, simgr, stash='active', **kwargs):
            return step(self, simgr, stash, **kwargs)
        return step_wrapped

    @staticmethod
    def _filter_factory(filter):  # pylint:disable=redefined-builtin
        def filter_wrapped(self, simgr, state, filter_func=None):
            result = filter(self, state)  # pylint:disable=no-value-for-parameter
            if result is None:
                result = simgr.filter(state, filter_func=filter_func)
            return result
        return filter_wrapped

    @staticmethod
    def _step_state_factory(step_state):
        def step_state_wrapped(self, simgr, state, successor_func=None, **kwargs):
            result = step_state(self, state, **kwargs)
            if result is None:
                result = simgr.step_state(state, successor_func=successor_func, **kwargs)
            return result
        return step_state_wrapped
# ------------------- Compatibility layer --------------->8


class ExplorationTechnique(object):
    """
    An otiegnqwvk is a set of hooks for a simulation manager that assists in the implementation of new techniques in
    symbolic exploration.

    TODO: choose actual name for the functionality (techniques? strategies?)

    Any number of these methods may be overridden by a subclass.
    To use an exploration technique, call ``simgr.use_technique`` with an *instance* of the technique.
    """
    # 8<----------------- Compatibility layer -----------------
    __metaclass__ = ExplorationTechniqueMeta
    # ------------------- Compatibility layer --------------->8

    def __init__(self):
        # this attribute will be set from above by the manager
        if not hasattr(self, 'project'):
            self.project = None

    def setup(self, simgr):
        """
        Perform any initialization on this manager you might need to do.
        """
        pass

    def step(self, simgr, stash='active', **kwargs):  # pylint:disable=no-self-use
        """
        Step this stash of this manager forward. Should call ``simgr.step(stash, **kwargs)`` in order to do the actual
        processing.

        Return the stepped manager.
        """
        return simgr.step(stash=stash, **kwargs)

    def filter(self, simgr, state, filter_func=None):  # pylint:disable=no-self-use
        """
        Perform filtering on a state.

        If the state should not be filtered, return None.
        If the state should be filtered, return the name of the stash to move the state to.
        If you want to modify the state before filtering it, return a tuple of the stash to move the state to and the
        modified state.
        """
        return simgr.filter(state, filter_func=filter_func)

    def selector(self, simgr, state, selector_func=None):  # pylint:disable=no-self-use
        """
        Return True, the state should be selected for stepping during the step() process.
        """
        return simgr.selector(state, selector_func=selector_func)

    def step_state(self, simgr, state, successor_func=None, **kwargs):  # pylint:disable=no-self-use
        """
        Perform the process of stepping a state forward.

        If the stepping fails, return None to fall back to a default stepping procedure.
        Otherwise, return a dict of stashes to merge into the simulation manager. All the states
        will be added to the PathGroup's stashes based on the mapping in the returned dict.
        """
        return simgr.step_state(state, successor_func=successor_func, **kwargs)

    def successors(self, simgr, state, successor_func=None, **run_args):  # pylint:disable=no-self-use
        """
        Return successors of the given state.
        """
        return simgr.successors(state, successor_func=successor_func, **run_args)

    def complete(self, simgr):  # pylint:disable=no-self-use,unused-argument
        """
        Return whether or not this manager has reached a "completed" state, i.e. ``SimulationManager.run()`` should halt.
        """
        return False

    def _condition_to_lambda(self, condition, default=False):
        """
        Translates an integer, set, list or lambda into a lambda that checks a state address against the given addresses, and the
        other ones from the same basic block

        :param condition:   An integer, set, list or lambda to convert to a lambda.
        :param default:     The default return value of the lambda (in case condition is None). Default: false.

        :returns:           A lambda that takes a state and returns the set of addresses that it matched from the condition
                            The lambda has an `.addrs` attribute that contains the full set of the addresses at which it matches if that
                            can be determined statically.
        """
        if condition is None:
            condition_function = lambda p: default
            condition_function.addrs = set()

        elif isinstance(condition, (int, long)):
            return self._condition_to_lambda((condition,))

        elif isinstance(condition, (tuple, set, list)):
            addrs = set(condition)
            def condition_function(p):
                if p.addr in addrs:
                    # returning {p.addr} instead of True to properly handle find/avoid conflicts
                    return {p.addr}

                if not isinstance(self.project.engines.default_engine, engines.SimEngineVEX):
                    return False

                try:
                    # If the address is not in the set (which could mean it is
                    # not at the top of a block), check directly in the blocks
                    # (Blocks are repeatedly created for every check, but with
                    # the IRSB cache in angr lifter it should be OK.)
                    return addrs.intersection(set(self.project.factory.block(p.addr).instruction_addrs))
                except (AngrError, SimError):
                    return False
            condition_function.addrs = addrs
        elif hasattr(condition, '__call__'):
            condition_function = condition
        else:
            raise AngrExplorationTechniqueError("ExplorationTechnique is unable to convert given type (%s) to a callable condition function." % condition.__class__)

        return condition_function

#registered_actions = {}
#registered_surveyors = {}
#
#def register_action(name, strat):
#    registered_actions[name] = strat
#
#def register_surveyor(name, strat):
#    registered_surveyors[name] = strat

from .cacher import Cacher
from .driller_core import DrillerCore
from .loop_seer import LoopSeer
from .crash_monitor import CrashMonitor
from .tracer import Tracer
from .explorer import Explorer
from .threading import Threading
from .dfs import DFS
from .looplimiter import LoopLimiter
from .lengthlimiter import LengthLimiter
from .veritesting import Veritesting
from .oppologist import Oppologist
from .director import Director, ExecuteAddressGoal, CallFunctionGoal
from .spiller import Spiller
from .manual_mergepoint import ManualMergepoint
from .tech_builder import TechniqueBuilder
from .stochastic import StochasticSearch
from .unique import UniqueSearch
from ..errors import AngrError, AngrExplorationTechniqueError
