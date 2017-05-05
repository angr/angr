from .knowledge.basic_plugins import BasicBlocksPlugin, FunctionBoundsPlugin, IndirectJumpsPlugin, LabelsPlugin, CommentsPlugin


class KnowledgeBase(object):
    """
    Represents a "model" of raw knowledge about a project.
    """
    def __init__(self, project, plugins=None):
        self._project = project

        if plugins is None:
            self._plugins = {}

            self.register_plugin('basic_blocks', BasicBlocks())
            self.register_plugin('functions', FunctionBounds())
            self.register_plugin('indirect_jumps', IndirectJumps())
            self.register_plugin('variables', VariableManager())
            self.register_plugin('labels', Labels())
            self.register_plugin('comments', Comments())
        else:
            self.plugins = plugins

    def get_plugin(self, name):
        return self._plugins[name]

    def register_plugin(self, name, plugin):
        self._plugins[name] = plugin

    def copy(self):
        new_plugins = {x: y.copy() for x, y in self._plugins.iteritems()}
        return KnowledgeBase(self._project, 

    @property
    def basic_blocks(self):
        return self.get_plugin('basic_blocks')

    @property
    def functions(self):
        return self.get_plugin('functions')

    @property
    def indirect_jumps(self):
        return self.get_plugin('indirect_jumps')

    @property
    def variables(self):
        return self.get_plugin('variables')

    @property
    def labels(self):
        return self.get_plugin('labels')

    @property
    def comments(self):
        return self.get_plugin('comments')
