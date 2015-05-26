import ana
import weakref

default_plugins = { }

# This is a base class for SimState plugins. A SimState plugin will be copied along with the state when the state is branched. They
# are intended to be used for things such as tracking open files, tracking heap details, and providing storage and persistence for SimProcedures.
class SimStatePlugin(ana.Storable):
    #__slots__ = [ 'state' ]

    def __init__(self):
        self.state = None

    # Sets a new state (for example, if the state has been branched)
    def set_state(self, state):
        if state is None or type(state).__name__ == 'weakproxy':
            self.state = state
        else:
            self.state = weakref.proxy(state)

    # Should return a copy of the state plugin.
    def copy(self):
        raise Exception("copy() not implement for %s", self.__class__.__name__)

    def merge(self, others, merge_flag, flag_values): # pylint: disable=W0613
        '''
        Should merge the state plugin with the provided others.

           others - the other state plugin
           merge_flag - a symbolic expression for the merge flag
           flag_values - the values to compare against to check which content should be used.

               self.symbolic_content = self.state.se.If(merge_flag == flag_values[0], self.symbolic_content, other.se.symbolic_content)

            Can return a sequence of constraints to be added to the state.
        '''
        raise Exception("merge() not implement for %s", self.__class__.__name__)

    def widen(self, others, merge_flag, flag_values):
        """
        The widening operation for plugins.
        """

        raise Exception('widen() not implemented for %s', self.__class__.__name__)

    @staticmethod
    def register_default(name, cls):
        if name in default_plugins:
            raise Exception("%s is already set as the default for %s" % (default_plugins[name], name))
        default_plugins[name] = cls
