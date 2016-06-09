class Strategy(object):
    """
    A search strategy is a set of hooks for the path group stepping process.

    Any number of these methods may be overridden by a subclass.
    To use a strategy, call ``pg.use_strategy``.
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

        :returns:       None or a tuple of lists: successors, unconstrained, unsat, pruned, errored
        """
        return None

    def step(self, pg, stash, **kwargs):
        """
        Step this stash of this path group forward.

        :returns:       The stepped path group
        """
        return pg.step(stash=stash, **kwargs)

    def filter(self, path):
        """
        Perform filtering on a path.

        :returns:       None if the path should not be filtered, or the name of a stash to which to move this path
        """
        return None

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
            condition = lambda p: {p.addr} if p.addr in addrs else \
                                  addrs.intersection(set(self.project.factory.block(p.addr).instruction_addrs))
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
