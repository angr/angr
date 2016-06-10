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
        # this attribute will be set from above by the path group
        self.project = None

    def setup(self, pg):
        """
        Perform any initialization on this path group you might need to do.
        """
        pass

    def step_path(self, path):
        """
        Perform the process of stepping a path forward.

        If the stepping fails, return None to fall back to a default stepping procedure.
        Otherwise, return a tuple of lists: successors, unconstrained, unsat, pruned, errored
        """
        return None

    def step(self, pg, stash, **kwargs):
        """
        Step this stash of this path group forward.

        Return the stepped path group.
        """
        return pg.step(stash=stash, **kwargs)

    def filter(self, path):
        """
        Perform filtering on a path.

        If the path should not be filtered, return None.
        If the path should be filtered, return the name of the stash to move the path to.
        If you want to modify the path before filtering it, return a tuple of the stash to move the path to and the
        modified path.
        """
        return None

    def complete(self, pg):
        """
        Return whether or not this path group has reached a "completed" state, i.e. ``pathgroup.run()`` should halt.
        """
        return False

    def _condition_to_lambda(self, condition, default=False):
        """
        Translates an integer, set or list into a lambda that checks a path address against the given addresses, and the
        other ones from the same basic block

        :param condition:   An integer, set, or list to convert to a lambda.
        :param default:     The default return value of the lambda (in case condition is None). Default: false.

        :returns:           A lambda that takes a path and returns the set of addresses that it matched from the condition
        """
        if condition is None:
            condition = lambda p: default

        if isinstance(condition, (int, long)):
            condition = (condition,)

        if isinstance(condition, (tuple, set, list)):
            addrs = set(condition)
            def condition(p):
                if p.addr in addrs:
                    return True

                try:
                    return addrs.intersection(set(self._project.factory.block(p.addr).instruction_addrs))
                except AngrError:
                    return False

        return condition

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
from .veritesting import Veritesting
