default_plugins = { }


class SimStatePlugin(object):
    """
    This is a base class for SimState plugins. A SimState plugin will be copied along with the state when the state is
    branched. They are intended to be used for things such as tracking open files, tracking heap details, and providing
    storage and persistence for SimProcedures.
    """

    #__slots__ = [ 'state' ]

    STRONGREF_STATE = False

    def __init__(self):
        self.state = None

    # Sets a new state (for example, if the state has been branched)
    def set_state(self, state):
        self.state = state

    def set_strongref_state(self, state):
        pass

    def __getstate__(self):
        d = dict(self.__dict__)
        d['state'] = None
        return d

    # Should return a copy of the state plugin.
    def copy(self):
        raise Exception("copy() not implement for %s" % self.__class__.__name__)

    def merge(self, others, merge_conditions, common_ancestor=None): #pylint:disable=unused-argument
        """
        Should merge the state plugin with the provided others. This will be called by ``state.merge()`` after copying
        the target state, so this should mutate the current instance to merge with the others.

        :param others: the other state plugin
        :param merge_conditions: a symbolic condition for each of the plugins
        :param common_ancestor: a common ancestor of this plugin and the others being merged
        :returns: True if the state plugins are actually merged.
        :rtype: bool
        """
        raise Exception("merge() not implement for %s" % self.__class__.__name__)

    def widen(self, others): #pylint:disable=unused-argument
        """
        The widening operation for plugins. Widening is a special kind of merging that produces a more general state
        from several more specific states. It is used only during intensive static analysis. The same behavior
        regarding copying and mutation from ``merge`` should be followed.

        :param others: the other state plugin

        :returns: True if the state plugin is actually widened.
        :rtype: bool
        """
        raise Exception('widen() not implemented for %s', self.__class__.__name__)

    @staticmethod
    def register_default(name, cls):
        if name in default_plugins:
            raise Exception("%s is already set as the default for %s" % (default_plugins[name], name))
        default_plugins[name] = cls

    def init_state(self):
        pass
