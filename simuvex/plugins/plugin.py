default_plugins = { }

# This is a base class for SimState plugins. A SimState plugin will be copied along with the state when the state is branched. They
# are intended to be used for things such as tracking open files, tracking heap details, and providing storage and persistence for SimProcedures.
class SimStatePlugin(object):
    #__slots__ = [ 'state' ]

    def __init__(self):
        self.state = None

    # Sets a new state (for example, if the state has been branched)
    def set_state(self, state):
        self.state = state

    def __getstate__(self):
        d = dict(self.__dict__)
        d['state'] = None
        return d

    # Should return a copy of the state plugin.
    def copy(self):
        raise Exception("copy() not implement for %s", self.__class__.__name__)

    def merge(self, others, merge_conditions): #pylint:disable=unused-argument
        """
        Should merge the state plugin with the provided others.

        :param others: the other state plugin
        :param merge_conditions: a symbolic condition for each of the plugins
        :returns: a merged plugin
        :rtype: SimStatePlugin
        """
        raise Exception("merge() not implement for %s", self.__class__.__name__)

    def widen(self, others): #pylint:disable=unused-argument
        """
        The widening operation for plugins.
        """

        raise Exception('widen() not implemented for %s', self.__class__.__name__)

    @staticmethod
    def register_default(name, cls):
        if name in default_plugins:
            raise Exception("%s is already set as the default for %s" % (default_plugins[name], name))
        default_plugins[name] = cls

    def init_state(self):
        pass
