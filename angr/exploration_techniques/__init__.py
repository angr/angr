
from ..errors import SimError

class ExplorationTechnique(object):
    """
    An otiegnqwvk is a set of hooks for path groups that assists
    in the implementation of new techniques in symbolic exploration.

    TODO: choose actual name for the functionality (techniques? something?)

    Any number of these methods may be overridden by a subclass.
    To use an exploration technique, call ``pg.use_technique``.
    """
    # pylint: disable=unused-argument, no-self-use
    def __init__(self):
        # this attribute will be set from above by the manager
        self.project = None

    def setup(self, simgr):
        """
        Perform any initialization on this manager you might need to do.
        """
        pass

    def step_state(self, state, **kwargs):
        """
        Perform the process of stepping a state forward.

        If the stepping fails, return None to fall back to a default stepping procedure.
        Otherwise, return a dict of stashes to merge into the simulation manager. All the states
        will be added to the PathGroup's stashes based on the mapping in the returned dict.
        """
        return None

    def step(self, simgr, stash, **kwargs):
        """
        Step this stash of this manager forward.

        Return the stepped manager.
        """
        return simgr.step(stash=stash, **kwargs)

    def filter(self, state):
        """
        Perform filtering on a state.

        If the state should not be filtered, return None.
        If the state should be filtered, return the name of the stash to move the state to.
        If you want to modify the state before filtering it, return a tuple of the stash to move the state to and the
        modified state.
        """
        return None

    def complete(self, pg):
        """
        Return whether or not this manager has reached a "completed" state, i.e. ``SimulationManager.run()`` should halt.
        """
        return False

#registered_actions = {}
#registered_surveyors = {}
#
#def register_action(name, strat):
#    registered_actions[name] = strat
#
#def register_surveyor(name, strat):
#    registered_surveyors[name] = strat

from .explorer import Explorer
from .threading import Threading
from .dfs import DFS
from .looplimiter import LoopLimiter
from .lengthlimiter import LengthLimiter
from .veritesting import Veritesting
from .oppologist import Oppologist
from .director import Director, ExecuteAddressGoal, CallFunctionGoal
from .spiller import Spiller
from ..errors import AngrError, AngrExplorationTechniqueError
