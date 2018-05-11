from angr.misc import PluginHub, PluginPreset


class ToolHub(PluginHub):
    """
    This class contains functions for all the registered tools.
    """

    def __init__(self, project):
        super(ToolHub, self).__init__()
        self.project = project

    def _init_plugin(self, plugin_cls):
        tool = object.__new__(plugin_cls)
        tool.project = self.project
        tool.__init__()
        return tool

    def __getstate__(self):
        state = super(ToolHub, self).__getstate__()
        return state, self.project

    def __setstate__(self, state):
        state, self.project = state
        super(ToolHub, self).__setstate__(state)


class Tool(object):
    """
    This is a base class for various tools.

    We define a tool here as a set of functions, which are logically grouped together
    and are bound to a one particular project. To better understand what the 'Tool' is
    consider its comparison to the 'Analysis' class:

    - An analysis represents, well, the actual analysis that can be done on the
    given binary. The goal of the analysis is to acquire some new knowledge about
    the program.

    - A tool is simply a set of related functionality, that is bound to one particular
    project.

    - An analysis must be instantiated every time a user wishes to acquire the new
    results from it. The analysis DOES NOT retain its internal state across
    different runs.

    - A tool is instantiated only once - upon plugin registration - an it DOES retain
    its state across different calls.

    - Generally speaking, in its abstraction, the analysis object interface exposes
    only a single function - 'conduct_analysis()'. The results of the analysis are
    to be accessed through the fields of the analysis instance.

    - A tool should provide one or many functions which may share some common data
    stored in self object. Each function should return the results of its invocation
    using the 'return' statement.

    :ivar project:  The project for this tool.
    :type project:  angr.Project
    """
    project = None

    def __init__(self, project=None):
        super(Tool, self).__init__()
        self.project = project or self.project

    def __getstate__(self):
        return self.project,

    def __setstate__(self, state):
        self.project, = state


class ToolSet(PluginPreset):
    pass
